from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from feature_extractor.core.errors import FeatureExtractorError
from feature_extractor.core.loader import fetch_packument
from feature_extractor.core.models import FeatureRow
from feature_extractor.core.output import append_error, prepare_outputs, write_dataset
from feature_extractor.core.pipeline import build_row
from feature_extractor.core.sources import LocalArchiveSnapshotSource
from feature_extractor.extractors.base import BaseExtractor

#: npm-malware-package-pairs는 전부 실제 악성 업데이트 사례를 다루는 저장소이므로
#: (meta.json 897개 전수 조사로 확인: status="ok"인 850개 전부가 정상->악성 구조,
#: 나머지 47개는 status가 http_error_404/no_clean_baseline_found로 애초에 제외됨) label은 고정값.
LOCAL_ARCHIVE_LABEL = 1


def iter_pair_dirs(
    archive_root: Path,
) -> Iterator[tuple[Path, dict[str, Any] | None, str | None]]:
    """archive_root(<campaign>/<package>/meta.json 구조) 전체를 순회하며,
    (package_dir, meta, exclusion_reason)을 내보낸다.

    exclusion_reason이 None이면 유효한 pair(meta는 status="ok"이고 normal_version/
    malicious_version_used가 모두 존재)이고, 아니면 그 사유를 담아 반환한다 — 호출부가
    이를 dataset.errors.csv에 남기도록 하기 위함이며, 여기서 임의로 label을 붙이거나
    건너뛰지 않는다.
    """
    for meta_path in sorted(archive_root.glob("*/*/meta.json")):
        package_dir = meta_path.parent
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            yield package_dir, None, f"failed to read/parse meta.json: {exc}"
            continue

        status = meta.get("status")
        normal_version = meta.get("normal_version")
        malicious_version = meta.get("malicious_version_used") or meta.get("malicious_version")

        if status != "ok" or not normal_version or not malicious_version:
            yield (
                package_dir,
                meta,
                f"excluded from label={LOCAL_ARCHIVE_LABEL} dataset: "
                f"status={status!r}, normal_version={normal_version!r}, "
                f"malicious_version={malicious_version!r}",
            )
            continue

        yield package_dir, meta, None


def run_local_archive_batch(
    archive_root: Path,
    output_csv_path: Path,
    errors_csv_path: Path,
    extractors: list[BaseExtractor],
    *,
    limit: int | None = None,
) -> None:
    """npm-malware-package-pairs 로컬 클론에서 실제 악성 pair를 읽어 dataset.csv를 만든다.

    package.json 본문은 <package_dir>/{normal,malicious}_raw에서 로컬로 읽고,
    publish timestamp는 registry의 packument time 맵에서 조회한다(버전이 registry에서
    삭제되어도 time 맵에는 남아있는 것으로 확인됨). 어느 쪽이든 실패하면(임의값을
    채우지 않고) 해당 pair를 errors_csv_path에 남기고 계속 진행한다.

    limit은 전체 dataset을 생성하기 전 소수의 pair로 먼저 검증할 때 쓰는 용도다.

    이전 실행의 결과 파일은 archive_root를 확인한 뒤에 비운다. 경로를 잘못 넣었거나
    archive의 상위 디렉터리를 가리키면 pair가 0개로 끝나면서 이전 결과만 지우게 되므로,
    그 전에 FileNotFoundError를 낸다.
    """
    if not archive_root.is_dir():
        raise FileNotFoundError(f"archive root is not a directory: {archive_root}")
    if next(archive_root.glob("*/*/meta.json"), None) is None:
        raise FileNotFoundError(
            f"no <campaign>/<package>/meta.json found under {archive_root}; "
            "is this the root of an npm-malware-package-pairs clone?"
        )
    prepare_outputs(output_csv_path, errors_csv_path)

    rows: list[FeatureRow] = []
    processed = 0

    for package_dir, meta, exclusion_reason in iter_pair_dirs(archive_root):
        if limit is not None and processed >= limit:
            break

        package_name = (meta or {}).get("package", package_dir.name)
        old_version = (meta or {}).get("normal_version", "")
        new_version = (meta or {}).get("malicious_version_used") or (meta or {}).get("malicious_version", "")

        if exclusion_reason is not None:
            append_error(
                errors_csv_path,
                source_ref=str(package_dir),
                package=package_name,
                old_version=old_version,
                new_version=new_version,
                reason=exclusion_reason,
            )
            continue

        processed += 1
        try:
            packument = fetch_packument(package_name)
            old_source = LocalArchiveSnapshotSource(package_dir / "normal_raw", packument)
            new_source = LocalArchiveSnapshotSource(package_dir / "malicious_raw", packument)
            row = build_row(
                package_name,
                old_version,
                new_version,
                LOCAL_ARCHIVE_LABEL,
                extractors,
                old_source=old_source,
                new_source=new_source,
            )
            rows.append(row)
        except FeatureExtractorError as exc:
            append_error(
                errors_csv_path,
                source_ref=str(package_dir),
                package=package_name,
                old_version=old_version,
                new_version=new_version,
                reason=str(exc),
            )

    write_dataset(output_csv_path, rows)
