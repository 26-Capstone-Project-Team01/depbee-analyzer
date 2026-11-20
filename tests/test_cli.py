from __future__ import annotations

from importlib.metadata import distribution
from pathlib import Path

import pytest

from depbee_analyzer.cli import EXIT_INVALID_INPUT, main


def test_installed_console_entry_opens_depbee_analyzer_help(capsys: pytest.CaptureFixture[str]) -> None:
    entries = distribution("depbee-analyzer").entry_points.select(group="console_scripts", name="depbee-analyzer")
    (entry,) = entries
    assert entry.load() is main
    with pytest.raises(SystemExit) as result:
        main(["--help"])
    assert result.value.code == 0
    assert "depbee-analyzer" in capsys.readouterr().out.splitlines()[0]


def test_batch_with_missing_pairs_file_prints_one_line_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "typo.csv"

    exit_code = main(["batch", "--pairs-file", str(missing), "--output", str(tmp_path / "dataset.csv")])

    stderr = capsys.readouterr().err
    assert exit_code == EXIT_INVALID_INPUT
    assert stderr.startswith("error: ")
    assert "typo.csv" in stderr
    assert "Traceback" not in stderr


def test_batch_local_with_missing_archive_root_prints_one_line_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "batch-local",
            "--archive-root",
            str(tmp_path / "typo"),
            "--output",
            str(tmp_path / "dataset.csv"),
        ]
    )

    stderr = capsys.readouterr().err
    assert exit_code == EXIT_INVALID_INPUT
    assert stderr.startswith("error: ")
    assert "Traceback" not in stderr


def test_batch_local_with_non_archive_directory_explains_expected_layout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    not_an_archive = tmp_path / "capstone"
    not_an_archive.mkdir()

    exit_code = main(
        [
            "batch-local",
            "--archive-root",
            str(not_an_archive),
            "--output",
            str(tmp_path / "dataset.csv"),
        ]
    )

    stderr = capsys.readouterr().err
    assert exit_code == EXIT_INVALID_INPUT
    assert "meta.json" in stderr
