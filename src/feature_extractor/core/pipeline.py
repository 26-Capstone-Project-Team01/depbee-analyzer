from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from feature_extractor.core.errors import FeatureExtractorError
from feature_extractor.core.models import FeatureRow
from feature_extractor.core.output import append_error, prepare_outputs, write_dataset
from feature_extractor.core.sources import RegistrySnapshotSource, SnapshotSource
from feature_extractor.extractors import EXTRACTOR_REGISTRY
from feature_extractor.extractors.base import BaseExtractor


def resolve_extractors(names: Iterable[str] | None) -> list[BaseExtractor]:
    """--extractors 값으로부터 실행할 extractor 인스턴스 목록을 만든다.

    names가 없으면(None) 등록된 전체 extractor를 기본으로 실행한다.
    특정 이름을 고르는 것은 개발/디버깅 용도이며, 최종 dataset 생성 시에는
    항상 전체 실행(names=None)을 사용한다.
    """
    selected_names = list(names) if names else list(EXTRACTOR_REGISTRY)
    try:
        return [EXTRACTOR_REGISTRY[name]() for name in selected_names]
    except KeyError as exc:
        known = ", ".join(sorted(EXTRACTOR_REGISTRY))
        raise ValueError(f"unknown extractor {exc.args[0]!r}; known extractors: {known}") from exc


def build_row(
    package: str,
    old_version: str,
    new_version: str,
    label: int,
    extractors: list[BaseExtractor],
    *,
    old_source: SnapshotSource | None = None,
    new_source: SnapshotSource | None = None,
) -> FeatureRow:
    """단일 package pair에 대해 선택된 extractor 전체를 실행해 FeatureRow를 만든다.

    old_source/new_source를 지정하지 않으면(기본값) 기존과 동일하게 npm registry에서
    조회한다 (RegistrySnapshotSource, 이 경우 하나의 인스턴스를 old/new가 공유해
    packument를 package당 1번만 fetch한다). npm-malware-package-pairs처럼 registry에서
    삭제된 버전을 다루려면 LocalArchiveSnapshotSource 등 다른 SnapshotSource를 명시적으로
    넘긴다 — 이 함수와 PackageJsonExtractor 자체는 어느 쪽이든 변경 없이 그대로 쓰인다.
    """
    if old_version == new_version:
        raise FeatureExtractorError(
            f"old_version and new_version are identical ({old_version!r}) for package {package!r}"
        )

    if old_source is None and new_source is None:
        shared_registry_source = RegistrySnapshotSource()
        old_source = shared_registry_source
        new_source = shared_registry_source
    else:
        old_source = old_source or RegistrySnapshotSource()
        new_source = new_source or RegistrySnapshotSource()

    # 선택된 extractor들이 필요로 하는 데이터의 합집합만큼만 loader에게 요청한다.
    # (예: package_json extractor만 선택되면 tarball을 내려받지 않는다.)
    needs_source = any("source" in extractor.required_data for extractor in extractors)

    old_snapshot = old_source.get_snapshot(package, old_version, include_source=needs_source)
    new_snapshot = new_source.get_snapshot(package, new_version, include_source=needs_source)

    features: dict[str, object] = {}
    for extractor in extractors:
        result = extractor.extract(old_snapshot, new_snapshot)
        overlap = features.keys() & result.keys()
        if overlap:
            raise FeatureExtractorError(
                f"extractor {extractor.name!r} produced feature name(s) already set by "
                f"another extractor: {sorted(overlap)}"
            )
        features.update(result)

    return FeatureRow(
        package=package,
        old_version=old_version,
        new_version=new_version,
        features=features,
        label=label,
    )


def run_batch(
    pairs_csv_path: Path,
    output_csv_path: Path,
    errors_csv_path: Path,
    extractors: list[BaseExtractor],
) -> None:
    """pairs.csv(package,old_version,new_version,label)를 읽어 dataset.csv를 만든다.

    개별 pair 처리 중 오류가 나도 batch 전체를 중단하지 않고, 해당 pair를
    errors_csv_path에 기록한 뒤 나머지 pair 처리를 계속한다.

    이전 실행의 결과 파일은 pairs 파일을 연 뒤에 비운다. pairs 경로를 잘못 넣으면
    여기서 먼저 실패하므로 이전 결과가 지워지지 않는다.
    """
    rows: list[FeatureRow] = []
    with pairs_csv_path.open(newline="", encoding="utf-8") as f:
        prepare_outputs(output_csv_path, errors_csv_path)
        reader = csv.DictReader(f)
        for line_number, row in enumerate(reader, start=2):  # 헤더가 1행이므로 데이터는 2행부터
            package = row["package"]
            old_version = row["old_version"]
            new_version = row["new_version"]
            label = int(row["label"])
            try:
                rows.append(build_row(package, old_version, new_version, label, extractors))
            except FeatureExtractorError as exc:
                append_error(
                    errors_csv_path,
                    source_ref=str(line_number),
                    package=package,
                    old_version=old_version,
                    new_version=new_version,
                    reason=str(exc),
                )

    write_dataset(output_csv_path, rows)
