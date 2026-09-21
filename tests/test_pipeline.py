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
    assert {e.name for e in extractors} == {"package_json"}


def test_resolve_extractors_unknown_name_raises_value_error() -> None:
    with pytest.raises(ValueError):
        resolve_extractors(["does_not_exist"])


@patch("feature_extractor.core.pipeline.fetch_packument")
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

    with patch("feature_extractor.core.pipeline.fetch_packument", return_value=PACKUMENT):
        with pytest.raises(FeatureExtractorError):
            build_row(
                "sample-pkg",
                "1.0.0",
                "1.0.1",
                label=0,
                extractors=[FakeExtractorA(), FakeExtractorB()],
            )


@patch("feature_extractor.core.pipeline.fetch_packument")
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
