from __future__ import annotations

import csv
from pathlib import Path

from depbee_analyzer.core.models import FeatureRow

ERRORS_CSV_HEADER = ["source_ref", "package", "old_version", "new_version", "reason"]


def prepare_outputs(output_csv_path: Path, errors_csv_path: Path) -> None:
    """batch 실행을 시작할 때 이전 실행의 dataset.csv와 errors.csv를 비운다.

    dataset.csv와 errors.csv는 같은 실행에서 나온 한 쌍이어야 "dataset 행 + errors 행 =
    입력 pair 수"가 맞는다. 이전 실행의 오류 행이 남거나 쌓이면 이미 해결된 pair가
    errors에 남고, 행마다 어느 실행에서 나왔는지 구분할 수도 없다.

    errors.csv는 헤더만 남기고, 실행 중에는 append_error()가 한 줄씩 추가한다.
    실행이 중간에 죽어도 그때까지의 오류 기록이 파일에 남도록 하기 위함이다.
    dataset.csv도 여기서 비워 두어, 실행이 중간에 죽으면 이전 결과 대신 빈 파일이
    남는다 (새 errors.csv와 옛 dataset.csv가 짝지어지는 것을 막는다).

    호출부는 입력(pairs 파일, archive 경로)이 유효한지 확인한 뒤에 이 함수를 불러야 한다.
    그래야 입력 경로를 잘못 넣었을 때 이전 실행의 결과를 지우지 않는다.
    """
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    output_csv_path.write_bytes(b"")

    errors_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with errors_csv_path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(ERRORS_CSV_HEADER)


def write_dataset(output_csv_path: Path, rows: list[FeatureRow]) -> None:
    """추출된 FeatureRow들을 하나의 dataset.csv로 덮어쓴다.

    rows가 비어 있어도 파일을 빈 상태로 덮어쓴다. 이전 실행의 dataset.csv가 남아
    이번 실행의 errors.csv와 짝지어지는 것을 막기 위함이다. feature 컬럼 목록은 행이
    있어야 알 수 있으므로, 이 경우에는 헤더 없이 빈 파일이 된다.
    """
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with output_csv_path.open("w", newline="", encoding="utf-8") as f:
        if not rows:
            return
        fieldnames = list(rows[0].to_flat_dict().keys())
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

    batch 실행에서는 prepare_outputs()가 먼저 파일을 비워 두므로, 여기서의 append는
    같은 실행 안에서만 누적된다.

    source_ref는 이 pair가 입력에서 어디였는지를 가리키는 식별자로, 입력 종류에 따라
    의미가 다르다 (batch: pairs.csv의 행 번호, batch-local: local archive 안의 패키지
    디렉터리 경로).
    """
    errors_csv_path.parent.mkdir(parents=True, exist_ok=True)
    is_new_file = not errors_csv_path.exists()
    with errors_csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new_file:
            writer.writerow(ERRORS_CSV_HEADER)
        writer.writerow([source_ref, package, old_version, new_version, reason])
