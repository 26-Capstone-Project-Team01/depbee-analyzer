#!/usr/bin/env python3
"""Static npm package-pair rules, importable by product and dataset evaluator.

Pass two already verified, safely extracted package roots. Package code,
scripts, workflows, and binaries are never executed. Rule findings are not
model features and do not alter any model input schema.
"""
from __future__ import annotations

import argparse
import base64
import difflib
import json
import pathlib
import re
import shlex
from dataclasses import asdict, dataclass
from typing import Mapping

RULESET_VERSION = '2026-11-16.1'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 80 * 1024 * 1024
CODE_EXT = {'.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx'}
RULES = (
    ('R_download_exec', 'review', '설치 명령이 명시적으로 받은 파일을 그대로 실행'),
    ('R_secret_send', 'high_evidence', '설치 경로가 자격정보를 읽어 외부로 전송'),
    ('R_ci_secret_send', 'high_evidence', '변경 CI 작업이 비밀정보를 수집해 외부로 전송'),
    ('R_install_root_wipe', 'high_evidence', '설치 훅에 루트 삭제 명령 추가'),
    ('R_remote_admin_auth_override', 'review', '원격 명령 봇의 사용자 인증 설정을 고정 계정으로 교체'),
    ('R_diff_obfuscation', 'review', '새 동적 실행·디코딩 코드가 diff에 추가'),
)
ROOT_WIPE = re.compile(r'\brm\s+-rf\s+--no-preserve-root\s+/(?=\s|;|&|[\'\"]|$)', re.I)
DYNAMIC = re.compile(r'\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(')
ENCODED = re.compile(r'\batob\s*\(|Buffer\.from|base64|fromCharCode|\\x[0-9a-fA-F]{2}', re.I)
REMOTE_URL = re.compile(r'https?://(?!localhost(?=[:/]|$)|127\.0\.0\.1(?=[:/]|$)|\[::1\](?=[:/]|$))[^\s"\']+', re.I)
HARD_TOKEN = re.compile(r'\bconst\s+token\s*=\s*[\'\"][^\'\"]{12,}[\'\"]\s*;')
HARD_ALLOWED = re.compile(r'\bconst\s+allowed\s*=\s*\[\s*\d+(?:\s*,\s*\d+)*\s*\]\s*;')


@dataclass(frozen=True)
class Finding:
    rule_id: str
    status: str  # hit | no_hit | unknown
    disposition: str  # high_evidence | review
    reason: str
    paths: tuple[str, ...] = ()
    lines: tuple[int, ...] = ()


def _text(data: bytes | None) -> str:
    return (data or b'').decode('utf-8', 'replace')


def _line(text: str, pattern: str) -> int:
    match = re.search(pattern, text, re.I)
    return text.count('\n', 0, match.start()) + 1 if match else 0


def _package(files: Mapping[str, bytes]) -> dict | None:
    try:
        obj = json.loads(_text(files.get('package.json')))
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


def _install_scripts(pkg: dict) -> dict[str, str]:
    scripts = pkg.get('scripts', {})
    return {k: v for k, v in scripts.items() if k in ('preinstall', 'install', 'postinstall') and isinstance(v, str)} if isinstance(scripts, dict) else {}


def _tokens(command: str) -> list[str]:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=';&|')
        lex.whitespace_split = True
        lex.commenters = ''
        return list(lex)
    except ValueError:
        return []


def _segments(command: str) -> list[list[str]]:
    parts: list[list[str]] = []
    current: list[str] = []
    for token in _tokens(command):
        if token in ('&&', ';', '||', '|', '&'):
            if current: parts.append(current)
            current = []
        else:
            current.append(token)
    if current: parts.append(current)
    return parts


def _download_output(segment: list[str]) -> str | None:
    if not segment or pathlib.PurePosixPath(segment[0]).name not in ('curl', 'wget'):
        return None
    cmd = pathlib.PurePosixPath(segment[0]).name
    if not any(token.startswith(('http://', 'https://')) for token in segment):
        return None
    options = ('-o', '--output') if cmd == 'curl' else ('-O', '--output-document')
    for i, token in enumerate(segment):
        if token in options and i + 1 < len(segment):
            return segment[i + 1]
        if token.startswith('--output=' if cmd == 'curl' else '--output-document='):
            return token.split('=', 1)[1]
    return None


def _same_path(left: str, right: str) -> bool:
    return left.removeprefix('./') == right.removeprefix('./')


def _executes(segment: list[str], downloaded: str) -> bool:
    if not segment: return False
    cmd = pathlib.PurePosixPath(segment[0]).name
    if cmd in ('sh', 'bash', 'node', 'python', 'python3', 'bun'):
        return any(_same_path(token, downloaded) for token in segment[1:])
    return _same_path(segment[0], downloaded)


def _download_exec(pkg: dict) -> list[tuple[str, str]]:
    result = []
    for hook, script in _install_scripts(pkg).items():
        parts = _segments(script)
        for i, part in enumerate(parts):
            file = _download_output(part)
            if file and not file.startswith('-') and any(_executes(later, file) for later in parts[i + 1:]):
                result.append((hook, file))
    return result


def _direct_token_post(pkg: dict) -> bool:
    for script in _install_scripts(pkg).values():
        # Keep the token source, POST data option and external URL in one curl command.
        for command in re.split(r'&&|\|\||[;\n]', script):
            if (re.search(r'\bcurl\b', command) and
                re.search(r'(?:-d|--data(?:-binary)?)\s*["\']?\$\(\s*gh\s+auth\s+token\s*\)', command, re.I) and
                REMOTE_URL.search(command)):
                return True
    return False


def _telemetry_upload(files: Mapping[str, bytes], pkg: dict) -> list[str]:
    result = []
    for script in _install_scripts(pkg).values():
        for ref in re.findall(r'\bnode\s+(?:\./)?([\w./-]+\.(?:js|cjs|mjs))\b', script, re.I):
            if ref not in files: continue
            source = _text(files[ref])
            obj = re.search(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{.{0,800}?\benv\s*:\s*process\.env', source, re.I | re.S)
            if not obj: continue
            var = re.escape(obj.group(1))
            conditions = (
                re.search(r'\.npmrc', source, re.I),
                re.search(rf'\b{var}\.\w+\s*=\s*fs\.readFileSync', source, re.I | re.S),
                re.search(rf'JSON\.stringify\s*\(\s*{var}\s*[,)]', source, re.I | re.S),
                re.search(r'gh[\'\"]\s*,\s*\[[\'\"]auth[\'\"]\s*,\s*[\'\"]token', source, re.I | re.S),
                re.search(r'/user/repos', source, re.I),
                re.search(r'private\s*:\s*false', source, re.I | re.S),
                re.search(r'/contents/', source, re.I),
                re.search(r'\bPUT\b', source, re.I),
                re.search(r'https\.request|fetch\s*\(', source, re.I),
            )
            if all(conditions): result.append(ref)
    return result


def _secret_send(files: Mapping[str, bytes], pkg: dict) -> tuple[str, ...]:
    paths = []
    if _direct_token_post(pkg): paths.append('package.json')
    for path in _telemetry_upload(files, pkg): paths.extend(('package.json', path))
    return tuple(sorted(set(paths)))


def _ci_secret_send(files: Mapping[str, bytes]) -> list[str]:
    result = []
    for path, data in files.items():
        if not path.startswith('.github/workflows/'): continue
        source = _text(data)
        if 'workflow_dispatch' not in source or not re.search(r'base64\s+(?:-d|--decode)[^\n|;]*\|\s*(?:bash|sh)', source, re.I):
            continue
        for token in re.findall(r'[A-Za-z0-9+/]{400,}={0,2}', source):
            try: decoded = base64.b64decode(token, validate=True).decode('utf-8', 'replace')
            except (ValueError, UnicodeError): continue
            if (re.search(r'curl[^\n]*--data-binary\s+@', decoded, re.I) and
                re.search(r'_post\s*\(\)|_post\s+["\']', decoded, re.I) and
                re.search(r'\.env|\.npmrc|/environ|GITHUB_WORKSPACE', decoded, re.I) and
                REMOTE_URL.search(decoded)):
                result.append(path); break
    return result


def _admin_override(files: Mapping[str, bytes], pkg: dict) -> bool:
    source = _text(files.get('src/index.js'))
    return bool(
        pkg.get('main') == 'src/index.js' and HARD_TOKEN.search(source) and HARD_ALLOWED.search(source)
        and 'new TelegramBot(token' in source and 'polling: true' in source
        and re.search(r'allowed\.includes\s*\(\s*msg\.from\.id\s*\)', source)
        and re.search(r'bot\.onText\s*\(\s*/\\/exec', source)
        and re.search(r'\bexecSync\s*\(\s*cmd\b', source)
    )


def _obfuscation(files: Mapping[str, bytes]) -> bool:
    return any(DYNAMIC.search(_text(data)) and ENCODED.search(_text(data))
               for path, data in files.items() if pathlib.PurePosixPath(path).suffix.lower() in CODE_EXT)


def _added(old: bytes | None, new: bytes) -> str:
    return '\n'.join(line[1:] for line in difflib.unified_diff(
        _text(old).splitlines(), _text(new).splitlines(), lineterm='')
        if line.startswith('+') and not line.startswith('+++'))


def scan_pair(old_files: Mapping[str, bytes], new_files: Mapping[str, bytes],
              *, incomplete: bool = False) -> list[Finding]:
    """Evaluate one pair; package roots are relative-path→bytes maps.

    `unknown` is returned when required input is missing or was size-limited.
    Do not turn an unknown result into a negative label.
    """
    definitions = {name: (disposition, description) for name, disposition, description in RULES}
    old_pkg = _package(old_files); new_pkg = _package(new_files)
    if old_pkg is None or new_pkg is None or not old_pkg.get('name') or old_pkg.get('name') != new_pkg.get('name'):
        return [Finding(name, 'unknown', disposition, 'package.json 누락·파싱 실패 또는 서로 다른 패키지')
                for name, disposition, _ in RULES]
    results: dict[str, Finding] = {}
    def put(name: str, hit: bool, reason: str, paths: tuple[str, ...] = (), lines: tuple[int, ...] = ()):
        disposition, _ = definitions[name]
        results[name] = Finding(name, 'hit' if hit else 'no_hit', disposition, reason, paths if hit else (), lines if hit else ())
    package_changed = old_files.get('package.json') != new_files.get('package.json')
    target = _download_exec(new_pkg); prior = _download_exec(old_pkg)
    download_hit = package_changed and bool(set(target) - set(prior))
    put('R_download_exec', download_hit,
        '새 설치 명령에서 다운로드 출력 경로와 뒤의 실행 경로가 일치' if download_hit else '신규 동일 파일 다운로드·실행 경로 미확인',
        ('package.json',), (_line(_text(new_files['package.json']), r'"(?:preinstall|install|postinstall)"'),))

    target_paths = _secret_send(new_files, new_pkg)
    prior_paths = _secret_send(old_files, old_pkg)
    secret_changed = package_changed or any(old_files.get(path) != new_files.get(path) for path in target_paths)
    secret_hit = bool(target_paths) and not prior_paths and secret_changed
    put('R_secret_send', secret_hit,
        '변경된 설치 경로가 자격정보 읽기와 외부 전송을 연결' if secret_hit else '신규 설치 경로의 자격정보 전송 미확인',
        target_paths, tuple(_line(_text(new_files.get(path)), r'\.npmrc|gh\s+auth\s+token') for path in target_paths))

    target_ci = _ci_secret_send(new_files); prior_ci = _ci_secret_send(old_files)
    ci_paths = tuple(sorted(path for path in target_ci if path not in prior_ci and old_files.get(path) != new_files.get(path)))
    put('R_ci_secret_send', bool(ci_paths),
        '새 CI 명령을 정적으로 해독해 비밀정보 수집과 외부 POST를 확인' if ci_paths else '신규 CI 비밀정보 외부 전송 미확인', ci_paths,
        tuple(_line(_text(new_files.get(path)), r'base64') for path in ci_paths))

    old_install = '\n'.join(_install_scripts(old_pkg).values())
    new_install = '\n'.join(_install_scripts(new_pkg).values())
    wipe_hit = package_changed and bool(ROOT_WIPE.search(new_install)) and not ROOT_WIPE.search(old_install)
    put('R_install_root_wipe', wipe_hit,
        '설치 훅에 루트 디렉터리 재귀·강제 삭제 명령 추가' if wipe_hit else '신규 루트 삭제 명령 미확인',
        ('package.json',), (_line(_text(new_files['package.json']), r'--no-preserve-root'),))

    old_source = _text(old_files.get('src/index.js'))
    new_source = _text(new_files.get('src/index.js'))
    admin_hit = bool(
        old_files.get('src/index.js') != new_files.get('src/index.js')
        and 'process.env.TELEGRAM_BOT_TOKEN' in old_source
        and 'process.env.ALLOWED_USER_IDS' in old_source
        and _admin_override(new_files, new_pkg)
        and not _admin_override(old_files, old_pkg)
    )
    put('R_remote_admin_auth_override', admin_hit,
        '환경변수 인증 설정을 고정 계정으로 바꾸고 원격 명령 실행 경로 유지' if admin_hit else '원격 관리 인증 경계 변경 미확인',
        ('src/index.js',), (_line(new_source, r'const\s+token\s*='),))

    obf_paths = []
    for path, data in new_files.items():
        if pathlib.PurePosixPath(path).suffix.lower() not in CODE_EXT or old_files.get(path) == data: continue
        text = _text(data)
        if not (DYNAMIC.search(text) and ENCODED.search(text)) or _obfuscation({path: old_files.get(path, b'')}): continue
        additions = _added(old_files.get(path), data)
        if DYNAMIC.search(additions) and ENCODED.search(additions): obf_paths.append(path)
    obf_paths = sorted(obf_paths)
    put('R_diff_obfuscation', bool(obf_paths),
        '동적 실행·디코딩 단서가 변경 파일의 추가 줄에 함께 등장; 악성 행위는 미확인' if obf_paths else '신규 난독화 단서 미확인',
        tuple(obf_paths), tuple(_line(_text(new_files[path]), r'\beval\s*\(|\bFunction\s*\(') for path in obf_paths))
    if incomplete:
        for name in ('R_secret_send', 'R_ci_secret_send', 'R_remote_admin_auth_override', 'R_diff_obfuscation'):
            finding = results[name]
            if finding.status == 'no_hit':
                results[name] = Finding(name, 'unknown', finding.disposition, '일부 파일이 크기 제한·링크·읽기 오류로 누락되어 미적중 확정 불가')
    return [results[name] for name, _, _ in RULES]


def read_root(root: pathlib.Path) -> tuple[dict[str, bytes], list[str]]:
    root = root.resolve(strict=True)
    files: dict[str, bytes] = {}; skipped: list[str] = []; total = 0
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            skipped.append(rel + ':symlink'); continue
        if not path.is_file(): continue
        try:
            size = path.stat().st_size
            if size > MAX_FILE or total + size > MAX_TOTAL:
                skipped.append(rel + ':size_limit'); continue
            data = path.read_bytes()
        except OSError:
            skipped.append(rel + ':read_error'); continue
        files[rel] = data; total += len(data)
    return files, skipped


def scan_pair_dirs(normal_root: pathlib.Path, target_root: pathlib.Path) -> dict:
    old, old_skipped = read_root(normal_root)
    new, new_skipped = read_root(target_root)
    findings = scan_pair(old, new, incomplete=bool(old_skipped or new_skipped))
    old_pkg, new_pkg = _package(old), _package(new)
    return {'ruleset_version': RULESET_VERSION,
            'package': (new_pkg or {}).get('name'),
            'normal_version': (old_pkg or {}).get('version'),
            'target_version': (new_pkg or {}).get('version'),
            'identity_match': bool(old_pkg and new_pkg and old_pkg.get('name') == new_pkg.get('name')),
            'findings': [asdict(finding) for finding in findings],
            'skipped': {'normal': old_skipped, 'target': new_skipped}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--normal-dir', type=pathlib.Path, required=True)
    parser.add_argument('--target-dir', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    result = scan_pair_dirs(args.normal_dir, args.target_dir)
    payload = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output: args.output.write_text(payload)
    else: print(payload, end='')


if __name__ == '__main__': main()
