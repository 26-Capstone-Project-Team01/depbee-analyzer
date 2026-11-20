from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from depbee_analyzer.cli import EXIT_INVALID_INPUT, main
from depbee_analyzer.core.manifest import read_manifest, run_manifest_batch
from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.core.pipeline import resolve_extractors

PACKUMENT = {
    "time": {
        "1.0.0": "2024-01-01T00:00:00.000Z",
        "1.0.1": "2024-01-02T00:00:00.000Z",
        "1.0.2": "2024-01-03T00:00:00.000Z",
    }
}
MANIFEST_HEADER = ["package", "old_version", "new_version", "label", "old_source", "new_source", "note"]


def _write_raw(raw_root: Path, name: str, version: str, scripts: dict | None = None) -> None:
    package_dir = raw_root / "package"
    package_dir.mkdir(parents=True)
    data = {"name": name, "version": version, **({"scripts": scripts} if scripts else {})}
    (package_dir / "package.json").write_text(json.dumps(data), encoding="utf-8")


def _write_manifest(path: Path, rows: list[list[str]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(MANIFEST_HEADER)
        writer.writerows(rows)
    return path


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class _FakeRegistrySource:
    """registry 대신 고정 package.json을 돌려주고, 닫혔는지 기록한다."""

    instances: list[_FakeRegistrySource] = []

    def __init__(self) -> None:
        self.closed = False
        _FakeRegistrySource.instances.append(self)

    def get_snapshot(self, package: str, version: str, *, include_source: bool = False) -> PackageVersionSnapshot:
        return PackageVersionSnapshot(
            package=package,
            version=version,
            published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            package_json={"name": package, "version": version},
            source_dir=None,
        )

    def close(self) -> None:
        self.closed = True


@patch("depbee_analyzer.core.manifest.fetch_packument", return_value=PACKUMENT)
def test_archive_old_and_new(_fetch, tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    _write_raw(archive / "camp" / "pkg" / "normal_raw", "pkg", "1.0.0")
    _write_raw(archive / "camp" / "pkg" / "malicious_raw", "pkg", "1.0.1", scripts={"postinstall": "node x"})
    manifest = _write_manifest(
        tmp_path / "m.csv",
        [["pkg", "1.0.0", "1.0.1", "1", "archive:camp/pkg/normal_raw", "archive:camp/pkg/malicious_raw", "x"]],
    )

    run_manifest_batch(
        manifest, tmp_path / "out.csv", tmp_path / "err.csv", resolve_extractors(["package_json"]), archive_root=archive
    )

    rows = _read(tmp_path / "out.csv")
    assert [(r["package"], r["old_version"], r["new_version"], r["label"]) for r in rows] == [("pkg", "1.0.0", "1.0.1", "1")]
    assert rows[0]["installScriptAdded"] == "True"
    assert _read(tmp_path / "err.csv") == []


@patch("depbee_analyzer.core.manifest.RegistrySnapshotSource", _FakeRegistrySource)
@patch("depbee_analyzer.core.manifest.fetch_packument", return_value=PACKUMENT)
def test_registry_baseline_with_archive_malicious_version(_fetch, tmp_path: Path) -> None:
    """교체된 baseline(registry)과 archive의 악성 버전을 한 pair로 비교한다."""
    _FakeRegistrySource.instances.clear()
    archive = tmp_path / "archive"
    _write_raw(archive / "camp" / "pkg" / "malicious_raw", "pkg", "1.0.2", scripts={"postinstall": "node x"})
    manifest = _write_manifest(
        tmp_path / "m.csv", [["pkg", "1.0.1", "1.0.2", "1", "registry", "archive:camp/pkg/malicious_raw", ""]]
    )

    run_manifest_batch(
        manifest, tmp_path / "out.csv", tmp_path / "err.csv", resolve_extractors(["package_json"]), archive_root=archive
    )

    rows = _read(tmp_path / "out.csv")
    assert rows[0]["old_version"] == "1.0.1"
    assert rows[0]["installScriptAdded"] == "True"
    assert len(_FakeRegistrySource.instances) == 1
    assert _FakeRegistrySource.instances[0].closed


@patch("depbee_analyzer.core.manifest.fetch_packument", return_value=PACKUMENT)
def test_pair_level_failure_goes_to_errors_and_batch_continues(_fetch, tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    (archive / "camp" / "broken" / "malicious_raw").mkdir(parents=True)  # package.json 없음
    _write_raw(archive / "camp" / "pkg" / "normal_raw", "pkg", "1.0.0")
    _write_raw(archive / "camp" / "pkg" / "malicious_raw", "pkg", "1.0.1")
    manifest = _write_manifest(
        tmp_path / "m.csv",
        [
            ["broken", "1.0.0", "1.0.1", "1", "archive:camp/pkg/normal_raw", "archive:camp/broken/malicious_raw", ""],
            ["pkg", "1.0.0", "1.0.1", "1", "archive:camp/pkg/normal_raw", "archive:camp/pkg/malicious_raw", ""],
        ],
    )

    run_manifest_batch(
        manifest, tmp_path / "out.csv", tmp_path / "err.csv", resolve_extractors(["package_json"]), archive_root=archive
    )

    assert [r["package"] for r in _read(tmp_path / "out.csv")] == ["pkg"]
    errors = _read(tmp_path / "err.csv")
    assert [(e["package"], e["source_ref"]) for e in errors] == [("broken", "2")]


@pytest.mark.parametrize(
    ("source", "archive_root_given", "message"),
    [
        ("archive:../outside", True, "outside"),
        ("archive:camp/pkg/normal_raw", False, "--archive-root"),
        ("tarball", True, "must be"),
    ],
)
def test_invalid_sources_are_rejected_before_outputs_are_touched(
    tmp_path: Path, source: str, archive_root_given: bool, message: str
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    manifest = _write_manifest(tmp_path / "m.csv", [["pkg", "1.0.0", "1.0.1", "0", source, "registry", ""]])
    output = tmp_path / "out.csv"
    output.write_text("previous result", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        run_manifest_batch(
            manifest,
            output,
            tmp_path / "err.csv",
            resolve_extractors(["package_json"]),
            archive_root=archive if archive_root_given else None,
        )

    assert output.read_text(encoding="utf-8") == "previous result"


def test_missing_columns_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "m.csv"
    path.write_text("package,old_version,new_version,label\npkg,1.0.0,1.0.1,0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="old_source"):
        read_manifest(path, None)


def test_cli_reports_invalid_manifest_as_input_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = _write_manifest(tmp_path / "m.csv", [["pkg", "1.0.0", "1.0.1", "0", "archive:x", "registry", ""]])

    code = main(["batch-manifest", "--manifest", str(manifest), "--output", str(tmp_path / "out.csv")])

    assert code == EXIT_INVALID_INPUT
    assert "--archive-root" in capsys.readouterr().err
