"""old/new의 출처를 pair마다 지정하는 manifest로 dataset을 만든다.

악성 pair는 새(악성) 버전이 registry에서 삭제된 경우가 많아 archive에서 읽어야 하지만,
baseline(old)을 archive에 없는 같은 release line의 버전으로 바꾸면 old는 registry에서
받아야 한다. batch(둘 다 registry)나 batch-local(둘 다 archive)로는 이 조합을 만들 수
없으므로, manifest의 old_source/new_source 컬럼으로 양쪽 출처를 따로 지정한다.

manifest 컬럼: package, old_version, new_version, label, old_source, new_source
(다른 컬럼은 무시한다). 출처 값은 다음 둘 중 하나다.

- ``registry``: npm registry에서 package.json과 tarball을 받는다.
- ``archive:<경로>``: archive_root 기준 상대 경로의 raw 디렉터리
  (예: ``canisterworm_2026-03/foo/malicious_raw``)에서 읽는다. publish 시각은
  registry packument의 time 맵에서 가져온다(버전이 삭제돼도 time 맵에는 남는다).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from feature_extractor.core.errors import FeatureExtractorError
from feature_extractor.core.loader import fetch_packument
from feature_extractor.core.models import FeatureRow
from feature_extractor.core.output import append_error, prepare_outputs, write_dataset
from feature_extractor.core.pipeline import build_row
from feature_extractor.core.sources import LocalArchiveSnapshotSource, RegistrySnapshotSource, SnapshotSource
from feature_extractor.extractors.base import BaseExtractor

REQUIRED_COLUMNS = ("package", "old_version", "new_version", "label", "old_source", "new_source")
REGISTRY = "registry"
ARCHIVE_PREFIX = "archive:"


@dataclass(frozen=True)
class _SourceSpec:
    #: None이면 registry, 아니면 archive 안의 raw 디렉터리 절대 경로
    archive_dir: Path | None


def _parse_source(value: str, archive_root: Path | None, line_number: int) -> _SourceSpec:
    """출처 값을 해석한다. 잘못된 값은 입력 오류로 보고 batch를 시작하기 전에 알린다."""
    if value == REGISTRY:
        return _SourceSpec(archive_dir=None)
    if not value.startswith(ARCHIVE_PREFIX):
        raise ValueError(
            f"manifest line {line_number}: source must be {REGISTRY!r} or '{ARCHIVE_PREFIX}<path>', got {value!r}"
        )
    if archive_root is None:
        raise ValueError(f"manifest line {line_number}: {value!r} needs --archive-root")
    relative = value[len(ARCHIVE_PREFIX):]
    root = archive_root.resolve()
    resolved = (root / relative).resolve()
    # 상대 경로가 archive 밖(예: ../)을 가리키면 대상 패키지가 아닌 파일을 읽게 되므로 거부한다.
    if not resolved.is_relative_to(root) or resolved == root:
        raise ValueError(f"manifest line {line_number}: archive path {relative!r} is outside {archive_root}")
    return _SourceSpec(archive_dir=resolved)


@dataclass(frozen=True)
class _ManifestRow:
    line_number: int
    package: str
    old_version: str
    new_version: str
    label: int
    old: _SourceSpec
    new: _SourceSpec


def read_manifest(manifest_csv_path: Path, archive_root: Path | None) -> list[_ManifestRow]:
    """manifest 전체를 먼저 검증한다. 한 행이라도 잘못되면 결과 파일을 건드리기 전에 ValueError를 낸다."""
    rows: list[_ManifestRow] = []
    with manifest_csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"manifest {manifest_csv_path} is missing column(s): {missing}")
        for line_number, row in enumerate(reader, start=2):  # 헤더가 1행
            try:
                label = int(row["label"])
            except ValueError as exc:
                raise ValueError(f"manifest line {line_number}: label must be an integer") from exc
            rows.append(
                _ManifestRow(
                    line_number=line_number,
                    package=row["package"],
                    old_version=row["old_version"],
                    new_version=row["new_version"],
                    label=label,
                    old=_parse_source(row["old_source"], archive_root, line_number),
                    new=_parse_source(row["new_source"], archive_root, line_number),
                )
            )
    return rows


def _build_manifest_row(row: _ManifestRow, extractors: list[BaseExtractor]) -> FeatureRow:
    if row.old.archive_dir is None and row.new.archive_dir is None:
        # 둘 다 registry면 build_row가 source 하나를 공유해 packument를 한 번만 받는다.
        return build_row(row.package, row.old_version, row.new_version, row.label, extractors)

    packument = fetch_packument(row.package)
    owned: list[SnapshotSource] = []

    def source_for(spec: _SourceSpec) -> SnapshotSource:
        if spec.archive_dir is not None:
            return LocalArchiveSnapshotSource(spec.archive_dir, packument)
        registry = RegistrySnapshotSource()
        owned.append(registry)
        return registry

    try:
        return build_row(
            row.package,
            row.old_version,
            row.new_version,
            row.label,
            extractors,
            old_source=source_for(row.old),
            new_source=source_for(row.new),
        )
    finally:
        for source in owned:
            source.close()


def run_manifest_batch(
    manifest_csv_path: Path,
    output_csv_path: Path,
    errors_csv_path: Path,
    extractors: list[BaseExtractor],
    *,
    archive_root: Path | None = None,
) -> None:
    """manifest의 pair마다 지정된 출처로 feature를 추출해 dataset.csv를 만든다.

    pair 단위 오류는 errors_csv_path에 남기고 계속 진행한다. manifest 자체가 잘못되면
    (컬럼 누락, 알 수 없는 출처, archive 밖 경로) 이전 결과를 지우기 전에 ValueError를 낸다.
    """
    if archive_root is not None and not archive_root.is_dir():
        raise FileNotFoundError(f"archive root is not a directory: {archive_root}")
    manifest = read_manifest(manifest_csv_path, archive_root)
    prepare_outputs(output_csv_path, errors_csv_path)

    rows: list[FeatureRow] = []
    for row in manifest:
        try:
            rows.append(_build_manifest_row(row, extractors))
        except FeatureExtractorError as exc:
            append_error(
                errors_csv_path,
                source_ref=str(row.line_number),
                package=row.package,
                old_version=row.old_version,
                new_version=row.new_version,
                reason=str(exc),
            )

    write_dataset(output_csv_path, rows)
