from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from feature_extractor.core.errors import ExtractionError
from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.core.source_files import MAX_FILE_BYTES, collect_source_files


def _snapshot(source_dir: Path | None) -> PackageVersionSnapshot:
    return PackageVersionSnapshot(
        package="sample-pkg",
        version="1.0.0",
        published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        package_json={"name": "sample-pkg", "version": "1.0.0"},
        source_dir=source_dir,
    )


def test_collects_js_files_recursively_with_posix_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("module.exports = require('./lib/format');", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "format.js").write_text("module.exports = {};", encoding="utf-8")

    file_set = collect_source_files(_snapshot(tmp_path))

    assert [f.relative_path for f in file_set.files] == ["index.js", "lib/format.js"]
    assert file_set.root == tmp_path
    assert len(file_set) == 2
    assert file_set.total_bytes > 0


def test_package_json_and_other_extensions_are_not_collected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "sample-pkg"}', encoding="utf-8")
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")
    (tmp_path / "index.d.ts").write_text("export {};", encoding="utf-8")
    (tmp_path / "index.js").write_text("module.exports = {};", encoding="utf-8")
    (tmp_path / "esm.mjs").write_text("export default 1;", encoding="utf-8")
    (tmp_path / "legacy.cjs").write_text("module.exports = 1;", encoding="utf-8")

    file_set = collect_source_files(_snapshot(tmp_path))

    assert [f.relative_path for f in file_set.files] == ["esm.mjs", "index.js", "legacy.cjs"]


def test_bundled_node_modules_is_excluded(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("module.exports = {};", encoding="utf-8")
    vendored = tmp_path / "node_modules" / "left-pad"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("module.exports = {};", encoding="utf-8")

    file_set = collect_source_files(_snapshot(tmp_path))

    assert [f.relative_path for f in file_set.files] == ["index.js"]


def test_by_relative_path_maps_each_file(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("module.exports = 1;", encoding="utf-8")

    mapping = collect_source_files(_snapshot(tmp_path)).by_relative_path()

    assert set(mapping) == {"index.js"}
    assert mapping["index.js"].text == "module.exports = 1;"


def test_non_utf8_file_falls_back_to_latin1_without_losing_bytes(tmp_path: Path) -> None:
    raw = b"var s = '\xff\xfe';"
    (tmp_path / "index.js").write_bytes(raw)

    file_set = collect_source_files(_snapshot(tmp_path))

    assert file_set.files[0].decoded_as == "latin-1"
    assert file_set.files[0].size_bytes == len(raw)
    assert file_set.files[0].text.encode("latin-1") == raw


def test_utf8_file_is_reported_as_utf8(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("var s = '안녕';", encoding="utf-8")

    file_set = collect_source_files(_snapshot(tmp_path))

    assert file_set.files[0].decoded_as == "utf-8"
    assert file_set.files[0].text == "var s = '안녕';"


def test_missing_source_dir_raises_extraction_error() -> None:
    with pytest.raises(ExtractionError):
        collect_source_files(_snapshot(None))


def test_source_dir_that_is_not_a_directory_raises_extraction_error(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "index.js"
    not_a_dir.write_text("module.exports = 1;", encoding="utf-8")

    with pytest.raises(ExtractionError):
        collect_source_files(_snapshot(not_a_dir))


def test_too_many_files_raises_instead_of_truncating(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"file{index}.js").write_text("module.exports = 1;", encoding="utf-8")

    with pytest.raises(ExtractionError):
        collect_source_files(_snapshot(tmp_path), max_file_count=2)


def test_oversized_file_raises_instead_of_skipping(tmp_path: Path) -> None:
    (tmp_path / "bundle.js").write_text("x" * 100, encoding="utf-8")

    with pytest.raises(ExtractionError):
        collect_source_files(_snapshot(tmp_path), max_file_bytes=50)


def test_default_size_limit_accepts_multi_megabyte_payload_bundles(tmp_path: Path) -> None:
    """기본 상한이 실제 악성 페이로드 크기보다 작으면 그 샘플이 통째로 빠진다.

    npm-malware-package-pairs의 bun_environment.js는 최대 약 9.7MB이고, 한때 8MB였던
    기본 상한 때문에 약 330개 악성 pair가 errors.csv로 빠질 뻔했다. 그 크기를 넘는
    합성 파일이 기본값으로 수집되는지 확인한다.
    """
    payload_size = 10 * 1024 * 1024
    assert payload_size < MAX_FILE_BYTES
    (tmp_path / "bun_environment.js").write_bytes(b"x" * payload_size)

    file_set = collect_source_files(_snapshot(tmp_path))

    assert [f.relative_path for f in file_set.files] == ["bun_environment.js"]
    assert file_set.files[0].size_bytes == payload_size


def test_empty_source_tree_returns_empty_set(tmp_path: Path) -> None:
    file_set = collect_source_files(_snapshot(tmp_path))

    assert len(file_set) == 0
    assert file_set.total_bytes == 0
