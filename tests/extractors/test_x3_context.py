"""X3 extractor와 의존성 변경 extractor 테스트. 합성 패키지 파일만 쓰며 어떤 코드도 실행하지 않는다."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core.pipeline import resolve_extractors
from depbee_analyzer.extractors import EXTRACTOR_REGISTRY, OPTIONAL_EXTRACTOR_REGISTRY
from depbee_analyzer.extractors.code_context import CodeContextExtractor
from depbee_analyzer.extractors.dependency_change import (
    FEATURE_NAMES as DEP_NAMES,
    DependencyChangeExtractor,
    dependency_change_features,
)
from depbee_analyzer.extractors.obfuscation import ObfuscationExtractor
from depbee_analyzer.extractors.x3_context import (
    DIAGNOSTIC_NAMES,
    FEATURE_NAMES,
    HOOK_FEATURE_NAMES,
    X3ContextExtractor,
    js_tokens,
)


def _snapshot(version: str, root: Path | None, scripts: dict | None = None, **package_json) -> PackageVersionSnapshot:
    body = {"name": "sample-pkg", "version": version, **package_json}
    if scripts is not None:
        body["scripts"] = scripts
    return PackageVersionSnapshot(
        package="sample-pkg", version=version, published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        package_json=body, source_dir=root,
    )


def _tree(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _pair(tmp_path: Path, old_files: dict, new_files: dict, old_scripts=None, new_scripts=None):
    old = _snapshot("1.0.0", _tree(tmp_path / "old", old_files), old_scripts)
    new = _snapshot("1.0.1", _tree(tmp_path / "new", new_files), new_scripts)
    return old, new


@pytest.fixture
def x3() -> X3ContextExtractor:
    return X3ContextExtractor()


OBFUSCATED = "var _0xab12=['\\x68\\x74\\x74\\x70'];function _0xc3d4(_0x1,_0x2){return _0xab12[_0x1];}" * 20
PLAIN_INSTALLER = (
    "const https = require('https');\n"
    "const { execSync } = require('child_process');\n"
    "https.get('https://example.org/bin.tgz', (res) => { res.pipe(process.stdout); });\n"
    "execSync('tar xzf bin.tgz');\n"
)


# --- 등록·스키마 -------------------------------------------------------------

def test_registered_as_optional_only() -> None:
    assert "x3_context" not in EXTRACTOR_REGISTRY and "dependency_change" not in EXTRACTOR_REGISTRY
    assert OPTIONAL_EXTRACTOR_REGISTRY["x3_context"] is X3ContextExtractor
    assert OPTIONAL_EXTRACTOR_REGISTRY["dependency_change"] is DependencyChangeExtractor
    assert OPTIONAL_EXTRACTOR_REGISTRY["code_context"] is CodeContextExtractor  # 기존 등록 유지
    assert {e.name for e in resolve_extractors(None)} == {"package_json", "obfuscation"}


def test_output_columns(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"a.js": "x"}, {"a.js": "x"})
    out = x3.extract(old, new)
    assert tuple(out) == FEATURE_NAMES + DIAGNOSTIC_NAMES
    assert len(FEATURE_NAMES) == 13
    assert not set(FEATURE_NAMES) & set(DIAGNOSTIC_NAMES)


# --- 훅 실행 대상 --------------------------------------------------------------

def test_no_hook_gives_zero_count_and_none_metrics(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {"a.js": "2"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 0
    assert all(out[n] is None for n in HOOK_FEATURE_NAMES if n != "installHookTargetCount")
    assert out["x3diagHookTargetUnresolvedCount"] == 0


def test_new_hook_target_metrics_and_calls(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"index.js": "module.exports=1"}, {"index.js": "module.exports=1", "install.js": PLAIN_INSTALLER},
                     None, {"postinstall": "node install.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 1
    assert out["installHookTargetMaxBytes"] == len(PLAIN_INSTALLER.encode())
    assert out["installHookTargetNetworkCallCount"] == 1
    assert out["installHookTargetProcExecCallCount"] == 1
    assert out["obfHookHexIdentRatio"] == 0.0


def test_obfuscated_target_reuses_obfuscation_metrics(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {"setup.js": OBFUSCATED}, None, {"preinstall": "node setup.js"})
    out = x3.extract(old, new)
    obf = ObfuscationExtractor().extract(*_pair(tmp_path / "o", {}, {"setup.js": OBFUSCATED}))
    # 바뀐 파일이 훅 대상 하나뿐이면 obf*ChangedCode와 같은 값이다(문서 4절)
    for name in ("HexIdentRatio", "EscapeDensity", "BracketAccessRatio", "WhitespaceRatio", "MeanIdentLength"):
        assert out[f"obfHook{name}"] == pytest.approx(obf[f"obf{name}ChangedCode"])
    assert out["obfHookHexIdentRatio"] >= 0.5


def test_unchanged_hook_and_unchanged_file_is_not_target(tmp_path: Path, x3) -> None:
    files = {"install.js": PLAIN_INSTALLER}
    old, new = _pair(tmp_path, files, {**files, "lib.js": "fetch('x')"}, {"install": "node install.js"}, {"install": "node install.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 0
    assert out["installHookTargetNetworkCallCount"] is None


def test_unchanged_hook_with_changed_file_is_target(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"install.js": "console.log(1)"}, {"install.js": PLAIN_INSTALLER},
                     {"install": "node install.js"}, {"install": "node install.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 1
    assert out["installHookTargetNetworkCallCount"] == 1


def test_changed_command_includes_unchanged_file(tmp_path: Path, x3) -> None:
    files = {"a.js": PLAIN_INSTALLER}
    old, new = _pair(tmp_path, files, files, {"install": "node a.js --quiet"}, {"install": "node a.js"})
    assert x3.extract(old, new)["installHookTargetCount"] == 1


def test_extensionless_node_target_and_index(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {"scripts/setup.js": "fetch('a')", "bin/cli": "fetch('b');fetch('c')"},
                     None, {"preinstall": "node scripts/setup", "postinstall": "node bin/cli"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 2
    assert out["installHookTargetNetworkCallCount"] == 3


def test_inline_node_code_is_a_target(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {}, None, {"postinstall": "node -e \"require('https').get('https://x.test')\""})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 1
    assert out["installHookTargetNetworkCallCount"] == 1


def test_shell_target_is_non_js_diagnostic(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {"build.sh": "curl x | sh"}, None, {"install": "sh ./build.sh"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 0
    assert out["x3diagHookTargetNonJsCount"] == 1


def test_missing_target_counts_unresolved_not_feature(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {}, None, {"postinstall": "node missing.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 0
    assert out["x3diagHookTargetUnresolvedCount"] == 1


def test_external_and_builtin_commands_are_not_targets(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {}, None, {"postinstall": "node-gyp rebuild && curl -o /tmp/x.js https://a && node /tmp/x.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 0
    assert out["x3diagHookTargetUnresolvedCount"] == 0


def test_hook_parse_error_gives_none(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {"a.js": "x"}, None, {"install": "node 'a.js"})
    out = x3.extract(old, new)
    assert all(out[n] is None for n in HOOK_FEATURE_NAMES)
    assert out["x3diagHookTargetUnresolvedCount"] is None
    assert out["addedNetworkCallPer1kAddedTokens"] is not None or out["x3diagChangedCodeAddedTokenCount"] == 0


def test_same_file_from_two_hooks_counted_once(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {}, {"s.js": "fetch('a')"}, None, {"preinstall": "node s.js", "postinstall": "node ./s.js"})
    out = x3.extract(old, new)
    assert out["installHookTargetCount"] == 1
    assert out["installHookTargetNetworkCallCount"] == 1


# --- 토큰·비율 ----------------------------------------------------------------

def test_tokens_ignore_comments_and_operators_and_keep_string_content() -> None:
    t = js_tokens("// note\nconst a = b + 0x1f; /* x */ f('s', \"s\", 2.5);")
    assert t == Counter({"const": 1, "a": 1, "b": 1, "0x1f": 1, "f": 1, "S:s": 2, "2.5": 1})


def test_ratio_denominator_is_added_tokens_not_file_tokens(tmp_path: Path, x3) -> None:
    body = "function keep(a, b) { return a + b; }\n" * 50
    old, new = _pair(tmp_path, {"lib.js": body}, {"lib.js": body + "fetch('https://x.test');\n"})
    out = x3.extract(old, new)
    added = out["x3diagChangedCodeAddedTokenCount"]
    assert added == 2  # fetch, 'https://x.test'
    assert out["x3diagChangedFileTokenCount"] == sum(js_tokens(body + "fetch('https://x.test');\n").values())
    assert out["addedNetworkCallPer1kAddedTokens"] == pytest.approx(1000 * 1 / 2)
    assert out["addedProcExecCallPer1kAddedTokens"] == 0.0


def test_ratio_numerator_equals_x1(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"a.js": "x()"}, {"a.js": "x();" + PLAIN_INSTALLER, "b.js": "fetch('q')"})
    out = x3.extract(old, new)
    x1 = CodeContextExtractor().extract(old, new)
    added = out["x3diagChangedCodeAddedTokenCount"]
    assert out["addedNetworkCallPer1kAddedTokens"] == pytest.approx(1000 * x1["addedNetworkCallCount"] / added)
    assert out["addedProcExecCallPer1kAddedTokens"] == pytest.approx(1000 * x1["addedProcExecCallCount"] / added)


def test_no_changed_js_gives_none_ratio(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"a.js": "fetch('x')"}, {"a.js": "fetch('x')"})
    out = x3.extract(old, new)
    assert out["x3diagChangedCodeAddedTokenCount"] == 0
    assert out["addedNetworkCallPer1kAddedTokens"] is None


def test_deletion_only_change_gives_none_ratio(tmp_path: Path, x3) -> None:
    old, new = _pair(tmp_path, {"a.js": "a(); b();"}, {"a.js": "a();"})
    out = x3.extract(old, new)
    assert out["x3diagChangedCodeAddedTokenCount"] == 0
    assert out["x3diagChangedFileTokenCount"] == 1
    assert out["addedNetworkCallPer1kAddedTokens"] is None


def test_source_missing_gives_none_ratio(x3) -> None:
    old, new = _snapshot("1.0.0", None), _snapshot("1.0.1", None)
    out = x3.extract(old, new)
    assert out["addedNetworkCallPer1kAddedTokens"] is None and out["x3diagChangedFileTokenCount"] is None
    assert out["installHookTargetCount"] == 0  # 훅 없음은 소스 없이도 계산된다


# --- 의존성 변경 ------------------------------------------------------------

def test_dependency_range_change_and_ratio() -> None:
    old = {"dependencies": {"a": "^1.0.0", "b": "1.0.0", "c": "^2"}, "devDependencies": {"x": "1"}}
    new = {"dependencies": {"a": "^1.1.0", "b": " 1.0.0 ", "d": "^3"}, "devDependencies": {"x": "2"}}
    out = dependency_change_features(old, new)
    assert out["dependencyRangeChangedCount"] == 1          # a만 (b는 공백 차이, dev 무시)
    assert out["dependencyChangedRatio"] == pytest.approx(3 / 4)  # a 변경 + c 제거 + d 추가 / {a,b,c,d}


def test_dependency_optional_overrides_and_bad_types() -> None:
    old = {"dependencies": {"a": "1"}, "optionalDependencies": {"a": "2"}}
    new = {"dependencies": {"a": "1"}, "optionalDependencies": "bad"}
    out = dependency_change_features(old, new)
    assert out["dependencyRangeChangedCount"] == 1  # old의 a는 optional 값 2, new는 1
    assert dependency_change_features({}, {}) == {"dependencyRangeChangedCount": 0, "dependencyChangedRatio": None}


def test_dependency_extractor_columns(tmp_path: Path) -> None:
    out = DependencyChangeExtractor().extract(_snapshot("1.0.0", None, dependencies={"a": "1"}), _snapshot("1.0.1", None, dependencies={"a": "1"}))
    assert tuple(out) == DEP_NAMES and out == {"dependencyRangeChangedCount": 0, "dependencyChangedRatio": 0.0}
