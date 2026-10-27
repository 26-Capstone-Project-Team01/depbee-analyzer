from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from feature_extractor.core.local_dataset import iter_pair_dirs, run_local_archive_batch
from feature_extractor.core.pipeline import resolve_extractors


def _write_package_json(base: Path, name: str, version: str, scripts: dict | None = None) -> None:
    package_dir = base / "package"
    package_dir.mkdir(parents=True)
    data = {"name": name, "version": version}
    if scripts:
        data["scripts"] = scripts
    (package_dir / "package.json").write_text(json.dumps(data), encoding="utf-8")


def _make_valid_pair(archive_root: Path, campaign: str, package_dir_name: str, package_name: str) -> None:
    package_dir = archive_root / "pairs" / campaign / package_dir_name
    package_dir.mkdir(parents=True)
    meta = {
        "package": package_name,
        "campaign": campaign,
        "status": "ok",
        "normal_version": "1.0.0",
        "malicious_version": "1.0.1",
        "malicious_version_used": "1.0.1",
    }
    (package_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    _write_package_json(package_dir / "normal_raw", package_name, "1.0.0")
    _write_package_json(package_dir / "malicious_raw", package_name, "1.0.1", scripts={"postinstall": "node x.js"})


def _make_excluded_pair(archive_root: Path, campaign: str, package_dir_name: str, package_name: str) -> None:
    package_dir = archive_root / "pairs" / campaign / package_dir_name
    package_dir.mkdir(parents=True)
    # 실제 저장소에서 관찰된 "예외" 스키마: normal_version이 아예 없고 status가 ok가 아님.
    meta = {
        "package": package_name,
        "campaign": campaign,
        "status": "http_error_404",
        "malicious_version": "2.0.0",
    }
    (package_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")


def test_iter_pair_dirs_separates_valid_and_excluded(tmp_path: Path) -> None:
    _make_valid_pair(tmp_path, "campaign-a", "pkg-good", "pkg-good")
    _make_excluded_pair(tmp_path, "campaign-a", "pkg-bad", "pkg-bad")

    results = list(iter_pair_dirs(tmp_path))
    reasons_by_package = {r[1]["package"]: r[2] for r in results}

    assert reasons_by_package["pkg-good"] is None
    assert reasons_by_package["pkg-bad"] is not None
    assert "http_error_404" in reasons_by_package["pkg-bad"]


def test_iter_pair_dirs_skips_pairs_under_excluded_reason_dirs(tmp_path: Path) -> None:
    # pairs/_excluded/<사유>/<pair>/는 학습·Test에 쓰지 않는 보관 위치라 status가 ok여도 읽지 않는다.
    _make_valid_pair(tmp_path, "campaign-a", "pkg-good", "pkg-good")
    _make_valid_pair(tmp_path, "_excluded/no_baseline", "pkg-kept-aside", "pkg-kept-aside")

    packages = [r[1]["package"] for r in iter_pair_dirs(tmp_path)]

    assert packages == ["pkg-good"]


@patch("feature_extractor.core.local_dataset.fetch_packument")
def test_run_local_archive_batch_writes_dataset_and_excludes_invalid(mock_fetch_packument, tmp_path: Path) -> None:
    archive_root = tmp_path / "archive"
    _make_valid_pair(archive_root, "campaign-a", "pkg-good", "pkg-good")
    _make_excluded_pair(archive_root, "campaign-a", "pkg-bad", "pkg-bad")

    mock_fetch_packument.return_value = {
        "time": {"1.0.0": "2024-01-01T00:00:00.000Z", "1.0.1": "2024-01-02T00:00:00.000Z"}
    }

    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"

    run_local_archive_batch(archive_root, output_csv, errors_csv, resolve_extractors(["package_json"]))

    with output_csv.open(newline="", encoding="utf-8") as f:
        dataset_rows = list(csv.DictReader(f))
    assert len(dataset_rows) == 1
    assert dataset_rows[0]["package"] == "pkg-good"
    assert dataset_rows[0]["label"] == "1"
    assert dataset_rows[0]["installScriptAdded"] == "True"

    with errors_csv.open(newline="", encoding="utf-8") as f:
        error_rows = list(csv.DictReader(f))
    assert len(error_rows) == 1
    assert error_rows[0]["package"] == "pkg-bad"


@patch("feature_extractor.core.local_dataset.fetch_packument")
def test_run_local_archive_batch_respects_limit(mock_fetch_packument, tmp_path: Path) -> None:
    archive_root = tmp_path / "archive"
    for i in range(3):
        _make_valid_pair(archive_root, "campaign-a", f"pkg-{i}", f"pkg-{i}")

    mock_fetch_packument.return_value = {
        "time": {"1.0.0": "2024-01-01T00:00:00.000Z", "1.0.1": "2024-01-02T00:00:00.000Z"}
    }

    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"

    run_local_archive_batch(
        archive_root, output_csv, errors_csv, resolve_extractors(["package_json"]), limit=2
    )

    with output_csv.open(newline="", encoding="utf-8") as f:
        dataset_rows = list(csv.DictReader(f))
    assert len(dataset_rows) == 2


def _read_dict_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@patch("feature_extractor.core.local_dataset.fetch_packument")
def test_full_run_after_limited_smoke_test_does_not_keep_its_errors(
    mock_fetch_packument, tmp_path: Path
) -> None:
    """--limit으로 먼저 시험 실행한 뒤 같은 경로로 전체 실행해도 errors가 섞이면 안 된다."""
    archive_root = tmp_path / "archive"
    _make_excluded_pair(archive_root, "campaign-a", "pkg-a-bad", "pkg-a-bad")
    _make_valid_pair(archive_root, "campaign-a", "pkg-b-good", "pkg-b-good")
    mock_fetch_packument.return_value = {
        "time": {"1.0.0": "2024-01-01T00:00:00.000Z", "1.0.1": "2024-01-02T00:00:00.000Z"}
    }
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    extractors = resolve_extractors(["package_json"])

    run_local_archive_batch(archive_root, output_csv, errors_csv, extractors, limit=1)
    run_local_archive_batch(archive_root, output_csv, errors_csv, extractors)

    assert [r["package"] for r in _read_dict_rows(output_csv)] == ["pkg-b-good"]
    assert [r["package"] for r in _read_dict_rows(errors_csv)] == ["pkg-a-bad"]


def test_missing_archive_root_keeps_previous_outputs(tmp_path: Path) -> None:
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    output_csv.write_text("previous dataset\n", encoding="utf-8")
    errors_csv.write_text("previous errors\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        run_local_archive_batch(
            tmp_path / "typo", output_csv, errors_csv, resolve_extractors(["package_json"])
        )

    assert output_csv.read_text(encoding="utf-8") == "previous dataset\n"
    assert errors_csv.read_text(encoding="utf-8") == "previous errors\n"


def test_archive_root_without_meta_json_keeps_previous_outputs(tmp_path: Path) -> None:
    """archive의 상위 디렉터리처럼 pair가 하나도 없는 경로를 넣으면 이전 결과를 지우지 않는다."""
    not_an_archive = tmp_path / "capstone"
    (not_an_archive / "feature-extractor" / "src").mkdir(parents=True)
    output_csv = tmp_path / "dataset.csv"
    errors_csv = tmp_path / "dataset.errors.csv"
    output_csv.write_text("previous dataset\n", encoding="utf-8")
    errors_csv.write_text("previous errors\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        run_local_archive_batch(
            not_an_archive, output_csv, errors_csv, resolve_extractors(["package_json"])
        )

    assert output_csv.read_text(encoding="utf-8") == "previous dataset\n"
    assert errors_csv.read_text(encoding="utf-8") == "previous errors\n"
