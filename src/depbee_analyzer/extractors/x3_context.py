"""X3 feature: 설치 훅이 실행하는 코드의 난독화·호출 지표, 변경 토큰 수로 정규화한 추가 호출 비율.

정의와 근거는 docs/x3-features.md. 정적 분석만 한다(코드·lifecycle script·셸 명령을 실행하지 않는다).
기존 X1(code_context)과 난독화(obfuscation) extractor의 함수를 그대로 가져다 쓰고, 그 모듈은 바꾸지 않는다.
기본 실행 목록에는 넣지 않는다(OPTIONAL_EXTRACTOR_REGISTRY).

결측(None) 규칙
- 훅 해석 실패(X1과 같은 조건: scripts 형식 오류, 셸 토큰화 실패) → 훅 관련 Feature 모두 None.
- 바뀐 훅 실행 표면의 JS 대상이 0개 → installHookTargetCount=0, 나머지 훅 Feature None.
- 소스 수집 실패(X1과 같은 조건) → 비율 2개와 토큰 진단 열 None.
- 추가 토큰 수(분모 A)가 0 → 비율 None.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from depbee_analyzer.core.errors import ExtractionError
from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core.source_files import (
    MAX_FILE_BYTES,
    MAX_FILE_COUNT,
    SOURCE_EXTENSIONS,
    SourceFile,
    SourceFileSet,
    collect_source_files,
)
from depbee_analyzer.extractors.base import BaseExtractor
from depbee_analyzer.extractors.code_context import (
    _NODE_LIKE,
    _HookParseError,
    _hook_targets,
    _install_hooks,
    _read_relative,
    _resolve,
    _split_commands,
    _VARIABLE,
    added_call_features,
    call_signatures,
    lex_js,
)
from depbee_analyzer.extractors.obfuscation import METRICS, aggregate, file_metrics

HOOK_FEATURE_NAMES = (
    "installHookTargetCount",
    "installHookTargetMaxBytes",
    *(f"obfHook{m.name}" for m in METRICS),
    "installHookTargetProcExecCallCount",
    "installHookTargetNetworkCallCount",
)
RATIO_FEATURE_NAMES = (
    "addedNetworkCallPer1kAddedTokens",
    "addedProcExecCallPer1kAddedTokens",
)
#: 모델 입력 후보.
FEATURE_NAMES = HOOK_FEATURE_NAMES + RATIO_FEATURE_NAMES
#: 진단 열(모델 입력 아님). 분모 B, 해석 실패 수 등.
DIAGNOSTIC_NAMES = (
    "x3diagChangedCodeAddedTokenCount",
    "x3diagChangedFileTokenCount",
    "x3diagHookTargetUnresolvedCount",
    "x3diagHookTargetNonJsCount",
)

#: 인라인 코드를 받는 node 계열 옵션(X1 _INLINE_FLAGS 중 코드를 받는 것만; `--run`은 스크립트 이름, `-c`는 문법 검사).
_INLINE_CODE_FLAGS = frozenset({"-e", "--eval", "-p", "--print"})

# ---------------------------------------------------------------------------
# 토큰
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"__S(\d+)__"                      # 문자열 리터럴 자리표시 → 내용 기준 토큰
    r"|__[RT]__"                       # 정규식 리터럴 / 치환 있는 템플릿 경계
    r"|0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?"   # 숫자
    r"|[A-Za-z_$][\w$]*"               # 단어(예약어 포함)
)


def js_tokens(text: str) -> Counter[str]:
    """JS 한 파일의 토큰 multiset. 주석은 빼고, 연산자·괄호는 세지 않는다(docs/x3-features.md 2.2)."""
    code, strings = lex_js(text)
    tokens: Counter[str] = Counter()
    for m in _TOKEN.finditer(code):
        if m.group(1) is not None:
            index = int(m.group(1))
            tokens["S:" + (strings[index] if index < len(strings) else "")] += 1
        else:
            tokens[m.group(0)] += 1
    return tokens


def changed_token_counts(old_files: SourceFileSet, new_files: SourceFileSet) -> tuple[int, int]:
    """(A: 추가된 토큰 수, B: 변경 파일 전체 토큰 수). 파일 집합은 added_call_features와 같다(추가되었거나 내용이 바뀐 JS)."""
    old_by_path = old_files.by_relative_path()
    added = total = 0
    for new_file in new_files.files:
        old_file = old_by_path.get(new_file.relative_path)
        if old_file is not None and old_file.text == new_file.text:
            continue
        new_tokens = js_tokens(new_file.text)
        old_tokens = js_tokens(old_file.text) if old_file is not None else Counter()
        added += sum((new_tokens - old_tokens).values())
        total += sum(new_tokens.values())
    return added, total


# ---------------------------------------------------------------------------
# 설치 훅 실행 대상
# ---------------------------------------------------------------------------

def _inline_codes(segment: list[str]) -> list[str]:
    """node 계열 인터프리터의 인라인 코드(`node -e "<code>"`)."""
    program = PurePosixPath(segment[0]).name
    if program not in _NODE_LIKE and not _VARIABLE.match(segment[0]):
        return []
    for i, arg in enumerate(segment[1:], start=1):
        if arg in _INLINE_CODE_FLAGS:
            return [segment[i + 1]] if i + 1 < len(segment) else []
        if not arg.startswith("-"):
            return []  # 파일 인자가 먼저 나오면 인라인이 아니다
    return []


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return content.decode("latin-1")  # source_files와 같은 폴백


def _is_js_target(relative: str, node_like: bool) -> bool:
    suffix = PurePosixPath(relative).suffix.lower()
    return suffix in SOURCE_EXTENSIONS or (node_like and suffix == "")


def hook_targets(
    old: PackageVersionSnapshot, new: PackageVersionSnapshot, max_file_bytes: int = MAX_FILE_BYTES
) -> tuple[list[SourceFile], int, int] | None:
    """바뀐 훅 실행 표면의 JS 대상(SourceFile), 해석 실패 수, 비JS 대상 수. 훅 해석 실패면 None."""
    try:
        old_commands = {k: _split_commands(v) for k, v in _install_hooks(old.package_json).items()}
        new_commands = {k: _split_commands(v) for k, v in _install_hooks(new.package_json).items()}
    except _HookParseError:
        return None
    targets: dict[str, SourceFile] = {}
    unresolved, non_js = 0, set()
    for key, commands in new_commands.items():
        segments = [s for s, _, _ in commands]
        command_changed = key not in old_commands or [s for s, _, _ in old_commands[key]] != segments
        if command_changed:
            for i, segment in enumerate(segments):
                for j, code in enumerate(_inline_codes(segment)):
                    path = f"<inline:{key}:{i}:{j}>"
                    targets[path] = SourceFile(path, len(code.encode("utf-8")), code, "utf-8")
        internal, _external = _hook_targets(commands)
        for ref, node_like in internal:
            resolved = _resolve(new.source_dir, ref, node_like, max_file_bytes)
            if resolved is None:
                unresolved += 1
                continue
            relative, content = resolved
            if relative in targets:
                continue
            if command_changed:
                include = True
            else:
                previous = _read_relative(old.source_dir, relative, max_file_bytes)
                if previous is None:
                    unresolved += 1
                    continue
                include = previous is False or previous != content
            if not include:
                continue
            if not _is_js_target(relative, node_like):
                non_js.add(relative)
                continue
            targets[relative] = SourceFile(relative, len(content), _decode(content), "utf-8")
    return list(targets.values()), unresolved, len(non_js)


def hook_target_features(files: list[SourceFile]) -> dict[str, Any]:
    if not files:
        return {name: (0 if name == "installHookTargetCount" else None) for name in HOOK_FEATURE_NAMES}
    metrics = {f.relative_path: file_metrics(f.text) for f in files}
    agg = aggregate(files, metrics) or {}
    proc = net = 0
    for f in files:
        p, n = call_signatures(f.text)
        proc += sum(p.values())
        net += sum(n.values())
    features: dict[str, Any] = {
        "installHookTargetCount": len(files),
        "installHookTargetMaxBytes": max(f.size_bytes for f in files),
    }
    for m in METRICS:
        features[f"obfHook{m.name}"] = agg.get(m.name)
    features["installHookTargetProcExecCallCount"] = proc
    features["installHookTargetNetworkCallCount"] = net
    return features


class X3ContextExtractor(BaseExtractor):
    """X3. 기본 실행에 포함되지 않으며 `--extractors x3_context`로 켠다."""

    name = "x3_context"
    required_data = frozenset({"package_json", "source"})

    def __init__(self, *, max_file_bytes: int = MAX_FILE_BYTES, max_file_count: int = MAX_FILE_COUNT) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_file_count = max_file_count

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        out: dict[str, Any] = {}
        hooks = hook_targets(old, new, self.max_file_bytes)
        if hooks is None:
            out.update({name: None for name in HOOK_FEATURE_NAMES})
            out["x3diagHookTargetUnresolvedCount"] = None
            out["x3diagHookTargetNonJsCount"] = None
        else:
            files, unresolved, non_js = hooks
            out.update(hook_target_features(files))
            out["x3diagHookTargetUnresolvedCount"] = unresolved
            out["x3diagHookTargetNonJsCount"] = non_js
        try:
            limits = {"max_file_bytes": self.max_file_bytes, "max_file_count": self.max_file_count}
            old_files = collect_source_files(old, **limits)
            new_files = collect_source_files(new, **limits)
        except ExtractionError:
            out.update({name: None for name in RATIO_FEATURE_NAMES})
            out["x3diagChangedCodeAddedTokenCount"] = None
            out["x3diagChangedFileTokenCount"] = None
        else:
            calls = added_call_features(old_files, new_files, (old.version, new.version))
            added, total = changed_token_counts(old_files, new_files)
            out["x3diagChangedCodeAddedTokenCount"] = added
            out["x3diagChangedFileTokenCount"] = total
            out["addedNetworkCallPer1kAddedTokens"] = 1000 * calls["addedNetworkCallCount"] / added if added else None
            out["addedProcExecCallPer1kAddedTokens"] = 1000 * calls["addedProcExecCallCount"] / added if added else None
        return {name: out[name] for name in FEATURE_NAMES + DIAGNOSTIC_NAMES}
