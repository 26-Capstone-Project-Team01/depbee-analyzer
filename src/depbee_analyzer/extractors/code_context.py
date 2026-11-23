"""X1 코드 문맥 feature: 설치 훅(A 유형)과 변경 JS의 실행·통신 호출(C 유형).

정적 분석만 한다. 대상 패키지의 코드, lifecycle script, 셸 명령을 실행하지 않고
npm install도 하지 않는다. 파일은 snapshot.source_dir 아래에서 읽기만 한다.

결측(None) 규칙: 계산할 수 없는 경우만 None이고, 계산했는데 해당 행동이 없으면 0/False다.
- A 유형: install 훅 명령을 셸 토큰으로 나누지 못하거나(따옴표 불일치 등) scripts 형식이
  잘못되면 None. 훅이 없으면 0/False.
- installHookRefFileChanged: 패키지 **내부** 실행 대상 파일만 본다. 내부 경로인데 파일을 찾지 못하거나
  (없는 파일, symlink, 크기 상한 초과) source가 없으면, 바뀐 내부 파일이 하나도 확인되지 않은 경우에 한해 None.
  외부 실행 대상(패키지 밖 경로, 설치 중 내려받은 파일, 다운로드 파이프)은 이 값에 영향을 주지 않는다.
- installHookNewExternalExecCount: new 훅에만 있는 외부 실행 대상 수. 파일 내용을 읽지 않으므로 source가
  없어도 계산된다. 외부 실행 자체를 악성 판정으로 쓰지 않는다(정상 설치기도 내려받아 실행한다).
- C 유형: 새로 생기거나 바뀐 호출 지점 수(호출 서명 = API + 인자의 문자열·숫자 리터럴, added_call_features 참고).
  소스 파일 수집이 실패하면(source 없음, 파일 수·크기 상한, 디렉터리 읽기 오류) None.
  바뀐 JS 파일이 없으면 0.

이 extractor는 규칙 스캐너(rules/diff_scan.py)의 hit/no_hit 판정을 쓰지 않으며, 그 모듈에
의존하지 않는다. 기본 실행 목록(EXTRACTOR_REGISTRY)에도 넣지 않는다(extractors/__init__.py).
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from depbee_analyzer.core.errors import ExtractionError
from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core.source_files import (
    MAX_FILE_BYTES,
    MAX_FILE_COUNT,
    SourceFile,
    SourceFileSet,
    collect_source_files,
)
from depbee_analyzer.extractors.base import BaseExtractor
from depbee_analyzer.extractors.package_json import INSTALL_SCRIPT_KEYS

HOOK_FEATURE_NAMES = (
    "installHookNewProgramCount",
    "installHookArgsChanged",
    "installHookRefFileChanged",
    "installHookNewExternalExecCount",
)
FEATURE_NAMES = HOOK_FEATURE_NAMES + (
    "addedProcExecCallCount",
    "addedNetworkCallCount",
)

# ---------------------------------------------------------------------------
# A 유형: install 훅 명령
# ---------------------------------------------------------------------------

#: 명령을 나누는 셸 제어 연산자.
_CONTROL = frozenset({"&&", "||", ";", "|", "&", ";;", "|&", "(", ")"})
#: 다음 토큰을 파일 이름으로 받는 리디렉션 연산자(그 토큰은 실행 프로그램이 아니다).
_REDIRECT = frozenset({">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", ">|"})
#: 실행 프로그램 앞에 붙어 뒤 명령을 실행하는 래퍼(래퍼 자신은 실행 프로그램으로 세지 않는다).
_WRAPPERS = frozenset({"env", "exec", "command", "nohup", "sudo", "doas", "time"})
#: 값을 하나 받는 래퍼 옵션(`sudo -u root node x`의 root는 프로그램이 아니다).
_WRAPPER_VALUE_OPTIONS = frozenset({"-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U"})
#: 다른 프로그램을 실행하지 않는 셸 내장 명령(프로그램·실행 대상에서 뺀다).
_BUILTINS = frozenset({"true", "false", ":", "exit", "cd", "export", "set", "unset"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: 명령 위치에 단독으로 온 환경 변수(`$NODE`, `${npm_node_execpath}`): 인터프리터로 본다.
_VARIABLE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")
#: 인자로 받은 파일을 실행하는 인터프리터.
_SHELLS = frozenset({"sh", "bash", "zsh", "dash"})
_INTERPRETERS = _SHELLS | frozenset(
    {"node", "nodejs", "python", "python3", "bun", "deno", "ts-node", "tsx", "perl", "ruby"}
)
#: 파일 대신 인라인 코드를 받는 옵션(이 경우 참조 파일이 없다).
#: `node --run <script>`은 package.json 스크립트 이름을 받으므로 파일 참조가 아니다.
_INLINE_FLAGS = frozenset({"-e", "--eval", "-p", "--print", "-c", "-i", "--run"})
#: `bun run <file>`, `deno run <file>`처럼 하위 명령 뒤에 파일을 받는 인터프리터.
_RUN_SUBCOMMAND = frozenset({"bun", "deno"})
_NODE_LIKE = frozenset({"node", "nodejs", "bun", "ts-node", "tsx"})
_SCRIPT_SUFFIXES = (".js", ".cjs", ".mjs", ".sh", ".py", ".ts")


class _HookParseError(Exception):
    """install 훅을 해석할 수 없음(값이 None이 되어야 함)."""


def _install_hooks(package_json: dict[str, Any]) -> dict[str, str]:
    scripts = package_json.get("scripts")
    if scripts is None:
        return {}
    if not isinstance(scripts, dict):
        raise _HookParseError("scripts is not an object")
    hooks = {}
    for key in INSTALL_SCRIPT_KEYS:
        if key in scripts:
            if not isinstance(scripts[key], str):
                raise _HookParseError(f"scripts.{key} is not a string")
            hooks[key] = scripts[key]
    return hooks


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:  # 따옴표 불일치 등
        raise _HookParseError(str(exc)) from exc


#: 단순 명령 하나: 토큰, 앞 연산자(첫 명령은 None), 출력 리디렉션 대상(`>`, `>>`).
_Command = tuple[list[str], str | None, list[str]]


def _split_commands(command: str, _depth: int = 0) -> list[_Command]:
    """셸 명령을 단순 명령 단위로 나눈다. 앞의 환경 변수 대입과 래퍼는 뺀다.

    `sh -c "..."`·`bash -c "..."`의 인자는 한 단계 더 나눠 그 안의 명령도 포함한다.
    `$(...)` 명령 치환과 변수 확장은 해석하지 않는다(정적 한계).
    """
    raw: list[_Command] = []
    current: list[str] = []
    outputs: list[str] = []
    op: str | None = None
    pending_redirect: str | None = None
    for token in _tokens(command):
        if pending_redirect is not None:
            if pending_redirect in (">", ">>", ">|", "&>"):
                outputs.append(token)
            pending_redirect = None
            continue
        if token in _REDIRECT:
            pending_redirect = token
            continue
        if token in _CONTROL:
            if current:
                raw.append((current, op, outputs))
            current, outputs, op = [], [], token
            continue
        current.append(token)
    if current:
        raw.append((current, op, outputs))

    result: list[_Command] = []
    for segment, previous_op, redirect_outputs in raw:
        segment = _strip_prefixes(segment)
        if not segment or segment[0] in _BUILTINS:
            continue
        result.append((segment, previous_op, redirect_outputs))
        program = PurePosixPath(segment[0]).name
        if program in _SHELLS and _depth < 2 and "-c" in segment[1:]:
            index = segment.index("-c", 1)
            if index + 1 < len(segment):
                result.extend(_split_commands(segment[index + 1], _depth + 1))
    return result


def _strip_prefixes(segment: list[str]) -> list[str]:
    """앞의 환경 변수 대입과 래퍼(및 래퍼 옵션)를 뺀다."""
    while segment:
        if _ASSIGNMENT.match(segment[0]):
            segment = segment[1:]
        elif segment[0] in _WRAPPERS:
            segment = segment[1:]
            while segment and segment[0].startswith("-"):
                segment = segment[2:] if segment[0] in _WRAPPER_VALUE_OPTIONS else segment[1:]
        else:
            break
    return segment


def command_segments(command: str) -> list[list[str]]:
    """셸 명령의 단순 명령 토큰 목록(_split_commands에서 연산자·리디렉션 정보를 뺀 것)."""
    return [segment for segment, _, _ in _split_commands(command)]


_DOWNLOADERS = frozenset({"curl", "wget"})


def _download_outputs(segment: list[str], redirect_outputs: list[str]) -> list[str]:
    """curl/wget 명령이 내려받아 쓰는 파일 경로(`-o`, `--output`, wget `-O`, `>` 리디렉션)."""
    program = PurePosixPath(segment[0]).name
    if program not in _DOWNLOADERS:
        return []
    short, long_ = ("o", "--output") if program == "curl" else ("O", "--output-document")
    paths = list(redirect_outputs)
    args = segment[1:]
    for i, arg in enumerate(args):
        if arg.startswith(long_ + "="):
            paths.append(arg.split("=", 1)[1])
        elif (arg == long_ or (arg.startswith("-") and not arg.startswith("--") and arg.endswith(short))) \
                and i + 1 < len(args):
            paths.append(args[i + 1])
        elif arg.startswith("-" + short) and len(arg) > 2 and not arg.startswith("--"):
            paths.append(arg[2:])  # -o/tmp/x, -O-
    return [p for p in paths if p and p != "-"]


def _external_target(ref: str, downloaded: set[str]) -> str | None:
    """실행 대상 경로가 패키지 밖이거나 설치 중 내려받은 파일이면 비교용 키. 아니면 None."""
    normalized = posixpath.normpath(ref)
    if normalized in downloaded:
        return f"download:{normalized}"
    # `$VAR/x`는 패키지 밖 위치로 본다. `$SCRIPT`처럼 변수 하나뿐이면 위치를 알 수 없으므로 외부로 단정하지 않는다
    # (내부 실행 대상으로 남아 installHookRefFileChanged가 해석 불가 → None).
    if ref.startswith(("/", "~")) or (ref.startswith("$") and "/" in ref) \
            or normalized == ".." or normalized.startswith("../"):
        return f"path:{normalized}"
    return None


def _hook_targets(commands: list[_Command]) -> tuple[list[tuple[str, bool]], set[str]]:
    """훅 하나의 (패키지 내부 실행 대상, 외부 실행 대상 키 집합).

    실행 대상은 _referenced_paths가 고른 위치(명령 위치의 경로, 인터프리터의 첫 파일 인자)만 본다.
    `cp /tmp/a b`처럼 인자로만 쓰인 경로는 실행 대상이 아니다.
    """
    internal: list[tuple[str, bool]] = []
    external: set[str] = set()
    downloaded: set[str] = set()
    previous: list[str] | None = None
    for segment, op, redirect_outputs in commands:
        program = PurePosixPath(segment[0]).name
        refs = _referenced_paths(segment)
        if op in ("|", "|&") and previous is not None and program in _INTERPRETERS and not refs:
            previous_program = PurePosixPath(previous[0]).name
            if previous_program in _DOWNLOADERS:
                external.add(f"pipe:{previous_program}|{program}")  # curl ... | sh
        for ref, node_like in refs:
            key = _external_target(ref, downloaded)
            if key is None:
                internal.append((ref, node_like))
            else:
                external.add(key)
        downloaded.update(posixpath.normpath(p) for p in _download_outputs(segment, redirect_outputs))
        previous = segment
    return internal, external


def _programs(segments: list[list[str]]) -> list[str]:
    return [PurePosixPath(segment[0]).name for segment in segments]


def _referenced_paths(segment: list[str]) -> list[tuple[str, bool]]:
    """단순 명령 하나가 직접 실행하는 파일 경로. (경로, node 방식 확장자 보완 여부)."""
    head = segment[0]
    program = PurePosixPath(head).name
    variable_program = bool(_VARIABLE.match(head))  # `$NODE lint.js`: 변수는 인터프리터(외부 경로 아님)
    refs: list[tuple[str, bool]] = []
    if program not in _INTERPRETERS and not variable_program and (
        head.startswith(("./", "../", "/", "~/", "$")) or head.endswith(_SCRIPT_SUFFIXES)
    ):
        refs.append((head, False))
    if program in _INTERPRETERS or variable_program:
        expect_run_target = False
        for arg in segment[1:]:
            if arg in _INLINE_FLAGS:
                break  # 인라인 코드·스크립트 이름: 참조 파일 없음(셸 -c는 command_segments가 펼친다)
            if arg.startswith("-"):
                continue
            if not expect_run_target and arg == "run" and (program in _RUN_SUBCOMMAND or variable_program):
                expect_run_target = True  # `bun run x.js`, `deno run x.ts`, `$npm_execpath run build`
                continue
            if expect_run_target and not ("/" in arg or arg.endswith(_SCRIPT_SUFFIXES)):
                break  # `bun run build`: package.json 스크립트 이름이지 파일이 아니다
            refs.append((arg, program in _NODE_LIKE or variable_program))
            break
    return refs


def _resolve(root: Path | None, ref: str, node_like: bool, max_bytes: int) -> tuple[str, bytes] | None:
    """패키지 루트 안의 일반 파일로 해석되면 (상대 경로, 내용). 아니면 None."""
    if root is None:
        return None
    path = PurePosixPath(ref)
    if path.is_absolute() or ".." in path.parts:
        return None
    candidates = [path]
    if node_like and path.suffix == "":
        candidates += [PurePosixPath(f"{path}.js"), PurePosixPath(f"{path}.cjs"),
                       PurePosixPath(f"{path}.mjs"), path / "index.js"]
    for candidate in candidates:
        relative = PurePosixPath(*[p for p in candidate.parts if p != "."]) if candidate.parts else candidate
        full = root.joinpath(*relative.parts)
        if full.is_symlink() or not full.is_file():
            continue
        try:
            if full.stat().st_size > max_bytes:
                return None
            return relative.as_posix(), full.read_bytes()
        except OSError:
            return None
    return None


def _read_relative(root: Path | None, relative: str, max_bytes: int) -> bytes | None | bool:
    """old 쪽 같은 경로의 내용. 없으면 False, 읽을 수 없으면 None."""
    if root is None:
        return None
    full = root.joinpath(*PurePosixPath(relative).parts)
    if not full.exists() and not full.is_symlink():
        return False
    if full.is_symlink() or not full.is_file():
        return None
    try:
        if full.stat().st_size > max_bytes:
            return None
        return full.read_bytes()
    except OSError:
        return None


def install_hook_features(
    old: PackageVersionSnapshot, new: PackageVersionSnapshot, max_file_bytes: int = MAX_FILE_BYTES
) -> dict[str, Any]:
    try:
        old_commands = {k: _split_commands(v) for k, v in _install_hooks(old.package_json).items()}
        new_commands = {k: _split_commands(v) for k, v in _install_hooks(new.package_json).items()}
    except _HookParseError:
        return {name: None for name in HOOK_FEATURE_NAMES}
    old_hooks = {k: [s for s, _, _ in v] for k, v in old_commands.items()}
    new_hooks = {k: [s for s, _, _ in v] for k, v in new_commands.items()}

    old_programs = {p for segments in old_hooks.values() for p in _programs(segments)}
    new_programs = {p for segments in new_hooks.values() for p in _programs(segments)}

    args_changed = any(
        new_hooks[key] != old_hooks[key]
        and Counter(_programs(new_hooks[key])) == Counter(_programs(old_hooks[key]))
        for key in new_hooks.keys() & old_hooks.keys()
    )

    old_external: set[str] = set()
    for commands in old_commands.values():
        old_external |= _hook_targets(commands)[1]
    new_external: set[str] = set()
    changed, unresolved = False, False
    for commands in new_commands.values():
        internal, external = _hook_targets(commands)
        new_external |= external
        for ref, node_like in internal:
            resolved = _resolve(new.source_dir, ref, node_like, max_file_bytes)
            if resolved is None:
                unresolved = True  # 패키지 안 파일이어야 하는데 확인할 수 없음
                continue
            relative, content = resolved
            previous = _read_relative(old.source_dir, relative, max_file_bytes)
            if previous is None:
                unresolved = True
            elif previous is False or previous != content:
                changed = True
    ref_changed: bool | None = True if changed else (None if unresolved else False)

    return {
        "installHookNewProgramCount": len(new_programs - old_programs),
        "installHookArgsChanged": args_changed,
        "installHookRefFileChanged": ref_changed,
        "installHookNewExternalExecCount": len(new_external - old_external),
    }


# ---------------------------------------------------------------------------
# C 유형: 변경 JS 파일의 실행·통신 호출
# ---------------------------------------------------------------------------

_INTEREST = re.compile(r"[/'\"`{}]")
_TEMPLATE_INTEREST = re.compile(r"[\\`$]")
_REGEX_PREFIX_WORDS = frozenset(
    {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
     "case", "do", "else", "yield", "await"}
)
_REGEX_PREFIX_CHARS = set("(,=:[!&|?{};+-*%<>~^")


def lex_js(text: str) -> tuple[str, list[str]]:
    """주석을 지우고 문자열·정규식 리터럴을 자리표시로 바꾼 코드와 문자열 표를 돌려준다.

    문자열 'x'·"x"·`x`(치환 없는 템플릿)는 ` __S<k>__ `로 바꾸고 내용은 표의 k번째에 둔다.
    `${...}` 안의 식은 코드로 남긴다. 정규식 리터럴은 ` __R__ `로 바꾼다. 완전한 JS 파서가
    아니며 닫히지 않은 리터럴은 그 줄(또는 파일) 끝까지로 본다. 예외를 내지 않는다.
    """
    out: list[str] = []
    strings: list[str] = []
    stack: list[int] = []  # 열린 ${...}의 중괄호 깊이
    i, n = 0, len(text)

    def last_significant() -> str:
        for piece in reversed(out):
            stripped = piece.rstrip()
            if stripped:
                return stripped
        return ""

    def regex_allowed() -> bool:
        prev = last_significant()
        if not prev:
            return True
        if prev[-1] in _REGEX_PREFIX_CHARS:
            return True
        word = re.search(r"[A-Za-z_$][\w$]*$", prev)
        return bool(word and word.group(0) in _REGEX_PREFIX_WORDS)

    def template(start: int) -> int:
        j = start
        while True:
            m = _TEMPLATE_INTEREST.search(text, j)
            if not m:
                strings.append(text[start:])
                out.append(f" __S{len(strings) - 1}__ ")
                return n
            k, c = m.start(), text[m.start()]
            if c == "\\":
                j = k + 2
            elif c == "`":
                strings.append(text[start:k])
                out.append(f" __S{len(strings) - 1}__ ")
                return k + 1
            elif text.startswith("${", k):
                out.append(" __T__ ")
                stack.append(0)
                return k + 2
            else:
                j = k + 1

    while i < n:
        m = _INTEREST.search(text, i)
        if not m:
            out.append(text[i:])
            break
        j, c = m.start(), text[m.start()]
        out.append(text[i:j])
        if c == "{":
            if stack:
                stack[-1] += 1
            out.append(c)
            i = j + 1
        elif c == "}":
            if stack and stack[-1] == 0:
                stack.pop()
                i = template(j + 1)
            else:
                if stack:
                    stack[-1] -= 1
                out.append(c)
                i = j + 1
        elif c in "'\"":
            k = j + 1
            while k < n and text[k] != c and text[k] != "\n":
                k += 2 if text[k] == "\\" else 1
            strings.append(text[j + 1:min(k, n)])
            out.append(f" __S{len(strings) - 1}__ ")
            i = k + 1 if k < n and text[k] == c else k
        elif c == "`":
            i = template(j + 1)
        elif text.startswith("//", j):
            k = text.find("\n", j)
            out.append(" ")
            i = n if k < 0 else k
        elif text.startswith("/*", j):
            k = text.find("*/", j + 2)
            out.append(" ")
            i = n if k < 0 else k + 2
        elif regex_allowed():
            k, in_class = j + 1, False
            while k < n and text[k] != "\n":
                ch = text[k]
                if ch == "\\":
                    k += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                k += 1
            k += 1
            while k < n and (text[k].isalpha()):
                k += 1
            out.append(" __R__ ")
            i = k
        else:
            out.append("/")
            i = j + 1
    return "".join(out), strings


_ID = r"[A-Za-z_$][\w$]*"
#: 모듈 이름 인자: 문자열 리터럴 하나 또는 리터럴끼리만 `+`로 이은 것(`'chi' + 'ld_process'`). 변수가 섞이면 해석하지 않는다.
_CONCAT = r"__S\d+__(?:\s*\+\s*__S\d+__)*"
#: `const req = createRequire(import.meta.url)` / `module.createRequire(__filename)`로 만든 require 함수.
#: 멤버 접근: `.name` 또는 리터럴(결합) 대괄호 `["na" + "me"]`. 변수 대괄호(`obj[key]`)는 해석하지 않는다.
_MEMBER = rf"(?:\.\s*({_ID})|\[\s*({_CONCAT})\s*\])"
_CREATE_REQUIRE_ALIAS = re.compile(rf"(?<![\w$.])({_ID})\s*=\s*(?:{_ID}\s*\.\s*)?createRequire\s*\(")
_IMPORT_DEFAULT = re.compile(rf"\bimport\s+({_ID})\s*(?:,\s*\{{[^{{}}]*\}}\s*)?from\s*__S(\d+)__")
_IMPORT_STAR = re.compile(rf"\bimport\s*\*\s*as\s+({_ID})\s+from\s*__S(\d+)__")
_IMPORT_NAMED = re.compile(rf"\bimport\s*(?:{_ID}\s*,\s*)?\{{([^{{}}]*)\}}\s*from\s*__S(\d+)__")


class _RequirePatterns:
    """파일 하나에서 require 역할을 하는 표현(require, __require, createRequire(...), 그 별칭) 기준 패턴."""

    def __init__(self, code: str) -> None:
        aliases = sorted({m.group(1) for m in _CREATE_REQUIRE_ALIAS.finditer(code)} - {"require", "__require"})
        callee = r"(?:__)?require|(?:{_ID}\s*\.\s*)?createRequire\s*\([^()]*\)".replace("{_ID}", _ID)
        if aliases:
            callee += "|" + "|".join(rf"(?<![\w$.]){re.escape(a)}" for a in aliases)
        req = rf"(?:{callee})\s*\(\s*({_CONCAT})\s*\)"
        self.alias = re.compile(rf"(?<![\w$.])({_ID})\s*=\s*{req}(?!\s*[.(\[])")
        self.destructure = re.compile(rf"\{{([^{{}}]*)\}}\s*=\s*{req}")
        #: `x = require('child_process').spawn` (호출하지 않고 함수를 담음)
        self.member_ref = re.compile(rf"(?<![\w$.])({_ID})\s*=\s*{req}\s*\.\s*({_ID})(?![\w$])(?!\s*\()")
        #: `require('cp').spawn(` 또는 리터럴 대괄호 접근 `require('cp')["sp" + "awn"](`
        self.direct_member = re.compile(rf"{req}\s*{_MEMBER}\s*\(")
        self.direct_call = re.compile(rf"{req}\s*\(")

#: 프로세스 실행 API.
PROC_MODULES = {"child_process": frozenset({"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"})}

_DNS = frozenset({"lookup", "resolve", "resolve4", "resolve6", "resolveAny", "resolveTxt", "resolveCname",
                  "resolveMx", "resolveNs", "resolveSrv", "reverse"})
#: 외부 통신 API(Node 내장 모듈: 메서드 호출).
NET_MODULES = {
    "http": frozenset({"request", "get"}),
    "https": frozenset({"request", "get"}),
    "http2": frozenset({"connect"}),
    "net": frozenset({"connect", "createConnection", "Socket"}),
    "tls": frozenset({"connect"}),
    "dgram": frozenset({"createSocket"}),
    "dns": _DNS,
    "dns/promises": _DNS,
}
#: 그 자체를 호출하는 HTTP·소켓 라이브러리(기본 내보내기 호출과 메서드 호출).
NET_CALLABLE_LIBRARIES = frozenset(
    {"axios", "node-fetch", "cross-fetch", "isomorphic-fetch", "got", "request", "superagent",
     "needle", "undici", "ws", "phin", "make-fetch-happen"}
)
_LIBRARY_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "request", "fetch"})
_GLOBAL_NET = [
    re.compile(r"(?<![\w$.])fetch\s*\("),
    re.compile(r"\bnew\s+(?:WebSocket|XMLHttpRequest|EventSource)\s*\("),
    re.compile(r"(?<![\w$])navigator\s*\.\s*sendBeacon\s*\("),
]


def _literal(strings: list[str], concat: str) -> str:
    return "".join(strings[int(k)] for k in _PLACEHOLDER.findall(concat))


def _member_name(strings: list[str], identifier: str | None, concat: str | None) -> str:
    """`.name` 또는 리터럴 대괄호 접근 `["na" + "me"]`의 멤버 이름."""
    return identifier if identifier else _literal(strings, concat or "")


def _module(strings: list[str], ref: str) -> str:
    """자리표시 번호 하나(`12`) 또는 리터럴 결합(`__S1__ + __S2__`)을 모듈 이름으로 바꾼다."""
    name = strings[int(ref)] if ref.isdigit() else "".join(strings[int(k)] for k in _PLACEHOLDER.findall(ref))
    return name[5:] if name.startswith("node:") else name


def _bindings(
    code: str, strings: list[str], req: _RequirePatterns
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """alias → 모듈, 직접 꺼낸 이름 → (모듈, 원래 export 이름)."""
    aliases: dict[str, str] = {}
    names: dict[str, tuple[str, str]] = {}
    for pattern in (req.alias, _IMPORT_DEFAULT, _IMPORT_STAR):
        for m in pattern.finditer(code):
            aliases[m.group(1)] = _module(strings, m.group(2))
    for m in req.member_ref.finditer(code):
        names[m.group(1)] = (_module(strings, m.group(2)), m.group(3))
    for alias, module in list(aliases.items()):
        # `const run = cp.spawn` (cp는 모듈 alias, 호출하지 않고 함수를 담음)
        pattern = re.compile(rf"(?<![\w$.])({_ID})\s*=\s*{re.escape(alias)}\s*\.\s*({_ID})(?![\w$])(?!\s*\()")
        for m in pattern.finditer(code):
            names[m.group(1)] = (module, m.group(2))
    for pattern, separator in ((req.destructure, ":"), (_IMPORT_NAMED, " as ")):
        for m in pattern.finditer(code):
            module = _module(strings, m.group(2))
            for item in m.group(1).split(","):
                item = item.strip()
                if not item or item.startswith("..."):
                    continue
                exported, _, local = item.partition(separator)
                local = (local or exported).strip().split("=")[0].strip()
                exported = exported.strip()
                if re.fullmatch(_ID, local) and re.fullmatch(_ID, exported):
                    names[local] = (module, exported)
    return aliases, names


#: 호출 인자 범위를 찾을 때 볼 최대 길이(비정상 입력에서 시간 소모를 막는다).
_MAX_ARG_SPAN = 4096
_PLACEHOLDER = re.compile(r"__S(\d+)__")
_MARKERS = re.compile(r"__[STR]\d*__")
_NUMBER = re.compile(r"(?<![\w$.])\d+(?:\.\d+)?(?![\w$])")

#: 호출 서명: (API 이름, 인자에 직접 쓴 문자열 리터럴, 숫자 리터럴).
CallSignature = tuple[str, tuple[str, ...], tuple[str, ...]]


def _argument_literals(code: str, strings: list[str], start: int) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """`(` 바로 뒤 start부터 짝이 맞는 `)`까지의 인자에서 문자열·숫자 리터럴을 순서대로 뽑는다.

    변수·식별자는 넣지 않는다. minified 번들은 빌드마다 변수 이름이 바뀌므로 넣으면 같은 호출이
    바뀐 호출로 잡힌다. 그래서 `exec(cmd)` → `exec(cmd2)`처럼 변수로만 전달된 대상 변경은 구분하지 못한다.
    치환이 있는 템플릿 리터럴(`${...}`)의 고정 텍스트도 담기지 않는다(lex_js가 버린다).
    """
    depth, i, end = 1, start, min(len(code), start + _MAX_ARG_SPAN)
    while i < end and depth:
        c = code[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    span = code[start:i - 1 if depth == 0 else i]
    literals = tuple(strings[int(k)] for k in _PLACEHOLDER.findall(span))
    numbers = tuple(_NUMBER.findall(_MARKERS.sub(" ", span)))
    return literals, numbers


def call_signatures(text: str) -> tuple[Counter[CallSignature], Counter[CallSignature]]:
    """JS 소스 한 파일의 프로세스 실행·외부 통신 호출 서명 multiset. 주석·문자열 안은 세지 않는다.

    API 이름은 별칭이 아니라 모듈과 export 이름으로 정규화한다(`cp.exec`와 `child_process.exec`가 같다).
    """
    code, strings = lex_js(text)
    req = _RequirePatterns(code)
    aliases, names = _bindings(code, strings, req)
    proc: dict[int, tuple[str, int]] = {}
    net: dict[int, tuple[str, int]] = {}

    def member_calls(alias: str, module: str, methods: frozenset[str], into: dict) -> None:
        pattern = re.compile(rf"(?<![\w$.]){re.escape(alias)}\s*{_MEMBER}\s*\(")
        for m in pattern.finditer(code):
            method = _member_name(strings, m.group(1), m.group(2))
            if method in methods:
                into[m.start()] = (f"{module}.{method}", m.end())

    def bare_calls(name: str, api: str, into: dict) -> None:
        for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}\s*\(", code):
            into[m.start()] = (api, m.end())

    for alias, module in aliases.items():
        if module in PROC_MODULES:
            member_calls(alias, module, PROC_MODULES[module], proc)
        elif module in NET_MODULES:
            member_calls(alias, module, NET_MODULES[module], net)
        elif module in NET_CALLABLE_LIBRARIES:
            bare_calls(alias, module, net)
            member_calls(alias, module, _LIBRARY_METHODS, net)
    for local, (module, exported) in names.items():
        if module in PROC_MODULES and exported in PROC_MODULES[module]:
            bare_calls(local, f"{module}.{exported}", proc)
        elif module in NET_MODULES and exported in NET_MODULES[module]:
            bare_calls(local, f"{module}.{exported}", net)
        elif module in NET_CALLABLE_LIBRARIES and exported in _LIBRARY_METHODS | {"default"}:
            bare_calls(local, module if exported == "default" else f"{module}.{exported}", net)
    for m in req.direct_member.finditer(code):
        module, method = _module(strings, m.group(1)), _member_name(strings, m.group(2), m.group(3))
        api = (f"{module}.{method}", m.end())
        if module in PROC_MODULES and method in PROC_MODULES[module]:
            proc[m.start()] = api
        elif module in NET_MODULES and method in NET_MODULES[module]:
            net[m.start()] = api
        elif module in NET_CALLABLE_LIBRARIES and method in _LIBRARY_METHODS:
            net[m.start()] = api
    for m in req.direct_call.finditer(code):
        module = _module(strings, m.group(1))
        if module in NET_CALLABLE_LIBRARIES:
            net[m.start()] = (module, m.end())
    for pattern in _GLOBAL_NET:
        for m in pattern.finditer(code):
            api = re.sub(r"^new\s+|\s|\($", "", m.group(0))
            net.setdefault(m.start(), (api, m.end()))

    def signatures(calls: dict[int, tuple[str, int]]) -> Counter[CallSignature]:
        return Counter((api, *_argument_literals(code, strings, end)) for api, end in calls.values())

    return signatures(proc), signatures(net)


def count_calls(text: str) -> tuple[int, int]:
    """JS 소스 한 파일의 (프로세스 실행 호출 수, 외부 통신 호출 수)."""
    proc, net = call_signatures(text)
    return sum(proc.values()), sum(net.values())


_VERSION_TOKEN = "\x00PKG_VERSION\x00"


def _without_versions(signatures: Counter[CallSignature], versions: tuple[str, ...]) -> Counter[CallSignature]:
    """문자열 리터럴 안의 비교 대상 버전 문자열(old·new 버전)을 같은 토큰으로 바꾼다.

    빌드가 자기 버전을 실행 인자에 넣는 패키지(예: esbuild의 `--version=0.19.12`)는 버전만 올라도 서명이
    바뀌어 '바뀐 호출'로 잡힌다. 두 버전 문자열 외의 리터럴은 바꾸지 않는다.
    """
    ordered = sorted({v for v in versions if v}, key=len, reverse=True)
    if not ordered:
        return signatures
    result: Counter[CallSignature] = Counter()
    for (api, literals, numbers), count in signatures.items():
        normalized = []
        for literal in literals:
            for version in ordered:
                literal = literal.replace(version, _VERSION_TOKEN)
            normalized.append(literal)
        result[(api, tuple(normalized), numbers)] += count
    return result


def added_call_features(
    old_files: SourceFileSet, new_files: SourceFileSet, versions: tuple[str, ...] = ()
) -> dict[str, int]:
    """추가·변경된 JS 파일마다, new 호출 서명 multiset에서 old 같은 경로의 서명 multiset을 뺀 개수를 더한다.

    호출 서명 = (API, 인자의 문자열·숫자 리터럴). 그래서 호출 수가 같아도 대상 리터럴이 바뀌거나
    (`fetch("a")` → `fetch("b")`), 호출 하나가 지워지고 다른 호출이 생기면 센다. 순서만 바뀌거나 지워지기만
    한 호출은 세지 않는다. 줄 단위 diff를 쓰지 않으므로 minified 번들의 한 줄 전체가 '추가'로 잡히지 않는다.
    versions(old·new 버전 문자열)는 리터럴 안에서 같은 토큰으로 바꿔 비교한다(_without_versions).
    """
    old_by_path = old_files.by_relative_path()
    proc = net = 0
    for new_file in new_files.files:
        old_file: SourceFile | None = old_by_path.get(new_file.relative_path)
        if old_file is not None and old_file.text == new_file.text:
            continue
        new_proc, new_net = call_signatures(new_file.text)
        old_proc, old_net = call_signatures(old_file.text) if old_file is not None else (Counter(), Counter())
        new_proc, new_net, old_proc, old_net = (
            _without_versions(c, versions) for c in (new_proc, new_net, old_proc, old_net)
        )
        proc += sum((new_proc - old_proc).values())
        net += sum((new_net - old_net).values())
    return {"addedProcExecCallCount": proc, "addedNetworkCallCount": net}


class CodeContextExtractor(BaseExtractor):
    """X1 코드 문맥 feature. 기본 실행에 포함되지 않으며 `--extractors code_context`로 켠다."""

    name = "code_context"
    required_data = frozenset({"package_json", "source"})

    def __init__(self, *, max_file_bytes: int = MAX_FILE_BYTES, max_file_count: int = MAX_FILE_COUNT) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_file_count = max_file_count

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        features = install_hook_features(old, new, self.max_file_bytes)
        try:
            limits = {"max_file_bytes": self.max_file_bytes, "max_file_count": self.max_file_count}
            old_files = collect_source_files(old, **limits)
            new_files = collect_source_files(new, **limits)
        except ExtractionError:
            features.update({"addedProcExecCallCount": None, "addedNetworkCallCount": None})
        else:
            features.update(added_call_features(old_files, new_files, (old.version, new.version)))
        return {name: features[name] for name in FEATURE_NAMES}
