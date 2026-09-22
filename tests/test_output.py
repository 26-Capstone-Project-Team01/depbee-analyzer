from __future__ import annotations

import csv
from pathlib import Path

from feature_extractor.core.models import FeatureRow
from feature_extractor.core.output import (
    ERRORS_CSV_HEADER,
    append_error,
    prepare_outputs,
    write_dataset,
)


def _read_rows(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _row(package: str) -> FeatureRow:
    return FeatureRow(
        package=package,
        old_version="1.0.0",
        new_version="1.0.1",
        features={"someFeature": 1},
        label=1,
    )


def test_prepare_outputs_resets_errors_to_header_only(tmp_path: Path) -> None:
    errors_csv = tmp_path / "dataset.errors.csv"
    append_error(
        errors_csv, source_ref="2", package="stale", old_version="1", new_version="2", reason="old run"
    )

    prepare_outputs(tmp_path / "dataset.csv", errors_csv)

    assert _read_rows(errors_csv) == [ERRORS_CSV_HEADER]


def test_prepare_outputs_truncates_previous_dataset(tmp_path: Path) -> None:
    output_csv = tmp_path / "dataset.csv"
    write_dataset(output_csv, [_row("stale")])

    prepare_outputs(output_csv, tmp_path / "dataset.errors.csv")

    assert output_csv.read_bytes() == b""


def test_prepare_outputs_creates_missing_parent_directories(tmp_path: Path) -> None:
    output_csv = tmp_path / "nested" / "dataset.csv"
    errors_csv = tmp_path / "other" / "dataset.errors.csv"

    prepare_outputs(output_csv, errors_csv)

    assert output_csv.exists()
    assert _read_rows(errors_csv) == [ERRORS_CSV_HEADER]


def test_append_error_after_prepare_keeps_a_single_header(tmp_path: Path) -> None:
    errors_csv = tmp_path / "dataset.errors.csv"
    prepare_outputs(tmp_path / "dataset.csv", errors_csv)

    append_error(errors_csv, source_ref="2", package="pkg", old_version="1", new_version="2", reason="boom")

    assert _read_rows(errors_csv) == [ERRORS_CSV_HEADER, ["2", "pkg", "1", "2", "boom"]]


def test_write_dataset_with_no_rows_overwrites_previous_file(tmp_path: Path) -> None:
    """성공한 행이 없어도 이전 실행의 dataset.csv가 남으면 안 된다."""
    output_csv = tmp_path / "dataset.csv"
    write_dataset(output_csv, [_row("stale")])

    write_dataset(output_csv, [])

    assert output_csv.read_bytes() == b""


def test_write_dataset_overwrites_instead_of_appending(tmp_path: Path) -> None:
    output_csv = tmp_path / "dataset.csv"
    write_dataset(output_csv, [_row("first")])

    write_dataset(output_csv, [_row("second")])

    rows = _read_rows(output_csv)
    assert len(rows) == 2
    assert rows[1][0] == "second"
