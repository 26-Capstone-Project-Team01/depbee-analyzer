from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from feature_extractor.core.errors import FeatureExtractorError
from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.core.pipeline import build_row, resolve_extractors, run_batch
from feature_extractor.core.sources import SnapshotSource
from feature_extractor.extractors.base import BaseExtractor

PACKUMENT = {
    "versions": {
        "1.0.0": {"name": "sample-pkg", "version": "1.0.0"},
        "1.0.1": {
            "name": "sample-pkg",
            "version": "1.0.1",
            "scripts": {"postinstall": "node hook.js"},
        },
    },
    "time": {
        "1.0.0": "2024-01-01T00:00:00.000Z",
        "1.0.1": "2024-01-02T00:00:00.000Z",
    },
}


def test_resolve_extractors_default_returns_all_registered() -> None:
    extractors = resolve_extractors(None)
    assert {e.name for e in extractors} == {"package_json", "obfuscation"}


def test_resolve_extractors_unknown_name_raises_value_error() -> None:
    with pytest.raises(ValueError):
        resolve_extractors(["does_not_exist"])


@patch("feature_extractor.core.sources.fetch_packument")
def test_build_row_merges_extractor_output_with_label(mock_fetch_packument) -> None:
    mock_fetch_packument.return_value = PACKUMENT
    extractors = resolve_extractors(["package_json"])

    row = build_row("sample-pkg", "1.0.0", "1.0.1", label=1, extractors=extractors)

    assert row.package == "sample-pkg"
    assert row.label == 1
    assert row.features["installScriptAdded"] is True
    assert row.features["updateType"] == "patch"
    assert row.features["updateInterval"] == 86400.0


def test_build_row_rejects_identical_versions() -> None:
    with pytest.raises(FeatureExtractorError):
        build_row("sample-pkg", "1.0.0", "1.0.0", label=0, extractors=resolve_extractors(None))


def test_build_row_raises_on_duplicate_feature_names() -> None:
    class FakeExtractorA(BaseExtractor):
        name = "fake_a"

        def extract(
            self, old: PackageVersionSnapshot, new: PackageVersionSnapshot
        ) -> dict[str, Any]:
            return {"shared_key": 1}

    class FakeExtractorB(BaseExtractor):
        name = "fake_b"

        def extract(
            self, old: PackageVersionSnapshot, new: PackageVersionSnapshot
        ) -> dict[str, Any]:
            return {"shared_key": 2}

    with patch("feature_extractor.core.sources.fetch_packument", return_value=PACKUMENT):
        with pytest.raises(FeatureExtractorError):
            build_row(
                "sample-pkg",
                "1.0.0",
                "1.0.1",
                label=0,
                extractors=[FakeExtractorA(), FakeExtractorB()],
            )


class _RecordingSource(SnapshotSource):
    """get_snapshot()에 넘어온 include_source 값을 기록하는 테스트용 source."""

    def __init__(self) -> None:
        self.include_source_calls: list[bool] = []

    def get_snapshot(
        self, package: str, version: str, *, include_source: bool = False
    ) -> PackageVersionSnapshot:
        self.include_source_calls.append(include_source)
        return PackageVersionSnapshot(
            package=package,
            version=version,
            published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            package_json={"name": package, "version": version},
            source_dir=None,
        )


class _NoSourceExtractor(BaseExtractor):
    name = "no_source"
    required_data = frozenset({"package_json"})

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        return {"no_source_ran": True}


class _SourceExtractor(BaseExtractor):
    name = "needs_source"
    required_data = frozenset({"package_json", "source"})

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        return {"needs_source_ran": True}


def test_build_row_requests_source_only_when_an_extractor_declares_it() -> None:
    """obfuscation처럼 required_data에 "source"를 선언한 extractor가 선택됐을 때만
    loader가 tarball을 받아야 한다. extractor나 CLI 사용자가 직접 켜지 않는다.
    """
    without_source = _RecordingSource()
    build_row(
        "sample-pkg",
        "1.0.0",
        "1.0.1",
        label=0,
        extractors=[_NoSourceExtractor()],
        old_source=without_source,
        new_source=without_source,
    )
    assert without_source.include_source_calls == [False, False]

    with_source = _RecordingSource()
    build_row(
        "sample-pkg",
        "1.0.0",
        "1.0.1",
        label=0,
        extractors=[_NoSourceExtractor(), _SourceExtractor()],
        old_source=with_source,
        new_source=with_source,
    )
    assert with_source.include_source_calls == [True, True]


@patch("feature_extractor.core.sources.fetch_packument")
def test_run_batch_writes_dataset_and_records_errors(mock_fetch_packument, tmp_path: Path) -> None:
    mock_fetch_packument.return_value = PACKUMENT

    pairs_csv = tmp_path / "pairs.csv"
    pairs_csv.write_text(
        "package,old_version,new_version,label\n"
        "sample-pkg,1.0.0,1.0.1,1\n"
        "sample-pkg,1.0.0,1.0.0,0\n",  # 두 번째 행은 old==new라 오류로 처리되어야 함
        encoding="utf-8",
    )
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"

    run_batch(pairs_csv, output_csv, errors_csv, resolve_extractors(["package_json"]))

    with output_csv.open(newline="", encoding="utf-8") as f:
        dataset_rows = list(csv.DictReader(f))
    assert len(dataset_rows) == 1
    assert dataset_rows[0]["package"] == "sample-pkg"
    assert dataset_rows[0]["label"] == "1"

    with errors_csv.open(newline="", encoding="utf-8") as f:
        error_rows = list(csv.DictReader(f))
    assert len(error_rows) == 1
    assert error_rows[0]["old_version"] == "1.0.0"
    assert error_rows[0]["new_version"] == "1.0.0"


def _read_dict_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@patch("feature_extractor.core.sources.fetch_packument")
def test_run_batch_rerun_to_same_paths_does_not_accumulate_errors(
    mock_fetch_packument, tmp_path: Path
) -> None:
    """같은 출력 경로로 다시 돌려도 dataset과 errors가 한 실행분의 짝으로 남아야 한다."""
    mock_fetch_packument.return_value = PACKUMENT
    pairs_csv = tmp_path / "pairs.csv"
    pairs_csv.write_text(
        "package,old_version,new_version,label\n"
        "sample-pkg,1.0.0,1.0.1,1\n"
        "sample-pkg,1.0.0,1.0.0,0\n",
        encoding="utf-8",
    )
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    extractors = resolve_extractors(["package_json"])

    run_batch(pairs_csv, output_csv, errors_csv, extractors)
    run_batch(pairs_csv, output_csv, errors_csv, extractors)

    assert len(_read_dict_rows(output_csv)) == 1
    assert len(_read_dict_rows(errors_csv)) == 1


@patch("feature_extractor.core.sources.fetch_packument")
def test_run_batch_where_every_pair_fails_clears_previous_dataset(
    mock_fetch_packument, tmp_path: Path
) -> None:
    """모든 pair가 실패한 실행 뒤에 이전 실행의 dataset.csv가 남아 있으면 안 된다."""
    mock_fetch_packument.return_value = PACKUMENT
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    extractors = resolve_extractors(["package_json"])

    good_pairs = tmp_path / "good.csv"
    good_pairs.write_text(
        "package,old_version,new_version,label\nsample-pkg,1.0.0,1.0.1,1\n", encoding="utf-8"
    )
    run_batch(good_pairs, output_csv, errors_csv, extractors)
    assert len(_read_dict_rows(output_csv)) == 1

    failing_pairs = tmp_path / "failing.csv"
    failing_pairs.write_text(
        "package,old_version,new_version,label\nsample-pkg,1.0.0,1.0.0,0\n", encoding="utf-8"
    )
    run_batch(failing_pairs, output_csv, errors_csv, extractors)

    assert output_csv.read_bytes() == b""
    assert len(_read_dict_rows(errors_csv)) == 1


def test_run_batch_with_missing_pairs_file_keeps_previous_outputs(tmp_path: Path) -> None:
    """pairs 경로를 잘못 넣은 실행이 이전 결과를 지우면 안 된다."""
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    output_csv.write_text("previous dataset\n", encoding="utf-8")
    errors_csv.write_text("previous errors\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        run_batch(tmp_path / "typo.csv", output_csv, errors_csv, resolve_extractors(["package_json"]))

    assert output_csv.read_text(encoding="utf-8") == "previous dataset\n"
    assert errors_csv.read_text(encoding="utf-8") == "previous errors\n"
