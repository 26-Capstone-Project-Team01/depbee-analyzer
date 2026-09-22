from __future__ import annotations

import csv
from pathlib import Path

from feature_extractor.core.models import FeatureRow


def write_dataset(output_csv_path: Path, rows: list[FeatureRow]) -> None:
    """추출된 FeatureRow들을 하나의 dataset.csv로 (덮어)쓴다."""
    if not rows:
        return

    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].to_flat_dict().keys())
    with output_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.to_flat_dict())


def append_error(
    errors_csv_path: Path,
    *,
    source_ref: str,
    package: str,
    old_version: str,
    new_version: str,
    reason: str,
) -> None:
    """실패한 pair 한 건을 dataset.errors.csv에 append한다 (batch가 계속 진행되도록).

    source_ref는 이 pair가 입력에서 어디였는지를 가리키는 식별자로, 입력 종류에 따라
    의미가 다르다 (batch: pairs.csv의 행 번호, batch-local: local archive 안의 패키지
    디렉터리 경로).
    """
    errors_csv_path.parent.mkdir(parents=True, exist_ok=True)
    is_new_file = not errors_csv_path.exists()
    with errors_csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new_file:
            writer.writerow(["source_ref", "package", "old_version", "new_version", "reason"])
        writer.writerow([source_ref, package, old_version, new_version, reason])
