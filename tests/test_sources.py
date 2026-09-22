from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from feature_extractor.core.errors import LoaderError
from feature_extractor.core.sources import LocalArchiveSnapshotSource, RegistrySnapshotSource

PACKUMENT = {
    "versions": {
        "1.0.0": {"name": "sample-pkg", "version": "1.0.0"},
        "1.0.1": {"name": "sample-pkg", "version": "1.0.1"},
    },
    "time": {
        "1.0.0": "2024-01-01T00:00:00.000Z",
        "1.0.1": "2024-01-02T00:00:00.000Z",
    },
}


@patch("feature_extractor.core.sources.fetch_packument")
def test_registry_source_fetches_packument_once_for_two_versions(mock_fetch_packument) -> None:
    mock_fetch_packument.return_value = PACKUMENT
    source = RegistrySnapshotSource()

    old_snapshot = source.get_snapshot("sample-pkg", "1.0.0")
    new_snapshot = source.get_snapshot("sample-pkg", "1.0.1")

    assert old_snapshot.version == "1.0.0"
    assert new_snapshot.version == "1.0.1"
    mock_fetch_packument.assert_called_once_with("sample-pkg")


def test_local_archive_source_reads_package_json_and_registry_time(tmp_path: Path) -> None:
    # 실제 malicious_raw처럼 예측 불가능한 임의 하위 경로 아래에 package.json을 둔다.
    raw_root = tmp_path / "malicious_raw"
    package_dir = raw_root / "tmp" / "tmpabc123" / "sample-pkg" / "package"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(
        '{"name": "sample-pkg", "version": "1.0.1", "scripts": {"postinstall": "node x.js"}}',
        encoding="utf-8",
    )

    source = LocalArchiveSnapshotSource(raw_root, PACKUMENT)
    snapshot = source.get_snapshot("sample-pkg", "1.0.1")

    assert snapshot.package_json["scripts"]["postinstall"] == "node x.js"
    assert snapshot.published_at.year == 2024
    assert snapshot.published_at.day == 2
    assert snapshot.source_dir is None


def test_local_archive_source_with_include_source_points_at_the_package_root(tmp_path: Path) -> None:
    """source_dir은 registry tarball 경로와 마찬가지로 package.json이 있는 디렉터리여야 한다."""
    raw_root = tmp_path / "malicious_raw"
    package_dir = raw_root / "tmp" / "tmpabc123" / "sample-pkg" / "package"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(
        '{"name": "sample-pkg", "version": "1.0.1"}', encoding="utf-8"
    )
    (package_dir / "index.js").write_text("module.exports = 1;", encoding="utf-8")

    source = LocalArchiveSnapshotSource(raw_root, PACKUMENT)
    snapshot = source.get_snapshot("sample-pkg", "1.0.1", include_source=True)

    assert snapshot.source_dir == package_dir
    assert (snapshot.source_dir / "package.json").is_file()
    assert (snapshot.source_dir / "index.js").is_file()


def test_local_archive_source_missing_package_json_raises_loader_error(tmp_path: Path) -> None:
    empty_root = tmp_path / "normal_raw"
    empty_root.mkdir()

    source = LocalArchiveSnapshotSource(empty_root, PACKUMENT)
    with pytest.raises(LoaderError):
        source.get_snapshot("sample-pkg", "1.0.0")


def test_local_archive_source_ambiguous_package_json_raises_loader_error(tmp_path: Path) -> None:
    raw_root = tmp_path / "malicious_raw"
    for i in range(2):
        d = raw_root / f"candidate{i}" / "package"
        d.mkdir(parents=True)
        (d / "package.json").write_text('{"name": "sample-pkg", "version": "1.0.1"}', encoding="utf-8")

    source = LocalArchiveSnapshotSource(raw_root, PACKUMENT)
    with pytest.raises(LoaderError):
        source.get_snapshot("sample-pkg", "1.0.1")


def test_local_archive_source_missing_registry_time_raises_loader_error(tmp_path: Path) -> None:
    raw_root = tmp_path / "malicious_raw" / "package"
    raw_root.mkdir(parents=True)
    (raw_root / "package.json").write_text('{"name": "sample-pkg", "version": "9.9.9"}', encoding="utf-8")

    source = LocalArchiveSnapshotSource(raw_root.parent, PACKUMENT)
    with pytest.raises(LoaderError):
        source.get_snapshot("sample-pkg", "9.9.9")  # PACKUMENT["time"]에 없는 버전
