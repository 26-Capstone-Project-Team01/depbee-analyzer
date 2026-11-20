from __future__ import annotations

import json
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from depbee_analyzer.core.errors import LoaderError
from depbee_analyzer.core.loader import build_snapshot, fetch_packument, get_publish_time
from depbee_analyzer.core.models import PackageVersionSnapshot


class SnapshotSource(ABC):
    """PackageVersionSnapshot을 어디서/어떻게 만드는지를 감추는 인터페이스.

    pipeline.build_row()는 이 인터페이스에만 의존하므로, extractor나 CLI의
    single/batch 동작은 어떤 SnapshotSource가 쓰이는지 몰라도 된다.
    """

    @abstractmethod
    def get_snapshot(
        self, package: str, version: str, *, include_source: bool = False
    ) -> PackageVersionSnapshot:
        raise NotImplementedError

    def close(self) -> None:
        """이 source가 만든 임시 자원을 정리한다. 반환한 snapshot의 source_dir은 이후 쓸 수 없다."""

    def __enter__(self) -> SnapshotSource:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class RegistrySnapshotSource(SnapshotSource):
    """npm registry에서 package.json과 publish 시각을 가져온다 (기존 loader.py 그대로 재사용).

    같은 인스턴스로 old/new를 모두 조회하면 packument를 package당 1번만 fetch하고
    재사용한다 — build_row()가 기본값(레지스트리 전용) 경로에서 쓰던 동작과 동일하다.
    """

    def __init__(self) -> None:
        self._packument_cache: dict[str, dict[str, Any]] = {}
        # include_source=True로 받은 tarball을 풀어 둘 디렉터리. 처음 필요할 때 만들고 close()에서 지운다.
        self._source_root: tempfile.TemporaryDirectory[str] | None = None

    def get_snapshot(
        self, package: str, version: str, *, include_source: bool = False
    ) -> PackageVersionSnapshot:
        packument = self._packument_cache.get(package)
        if packument is None:
            packument = fetch_packument(package)
            self._packument_cache[package] = packument
        source_parent_dir = None
        if include_source:
            if self._source_root is None:
                self._source_root = tempfile.TemporaryDirectory(
                    prefix="feature_extractor_src_", ignore_cleanup_errors=True
                )
            source_parent_dir = Path(self._source_root.name)
        return build_snapshot(
            packument, package, version, include_source=include_source, source_parent_dir=source_parent_dir
        )

    def close(self) -> None:
        """받아서 풀어 둔 tarball을 모두 지운다.

        지우지 않으면 batch 실행에서 pair마다 두 버전의 소스 트리가 시스템 임시 디렉터리에 쌓인다.
        """
        if self._source_root is not None:
            self._source_root.cleanup()
            self._source_root = None


class LocalArchiveSnapshotSource(SnapshotSource):
    """npm-malware-package-pairs처럼 로컬에 보존된, registry에서 이미 삭제된
    버전을 다루기 위한 source. package.json 본문은 로컬 raw 디렉터리에서 읽고,
    publish 시각은 (registry에서 여전히 조회 가능한) packument의 time 맵에서 가져온다.

    raw_root는 <package_dir>/normal_raw 또는 <package_dir>/malicious_raw 같은
    디렉터리이며, 그 안에서 npm tarball 관례대로 ".../package/package.json"
    형태의 파일을 찾는다 (malicious_raw는 실제로 "tmp/<임의문자열>/<name>/package/"처럼
    예측 불가능한 하위 경로를 갖는 것으로 확인되어, 고정 경로 대신 탐색한다).
    """

    def __init__(self, raw_root: Path, packument: dict[str, Any]) -> None:
        self._raw_root = raw_root
        self._packument = packument

    def get_snapshot(
        self, package: str, version: str, *, include_source: bool = False
    ) -> PackageVersionSnapshot:
        package_json_path = _find_package_json(self._raw_root)
        try:
            package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LoaderError(f"failed to read {package_json_path}: {exc}") from exc

        published_at = get_publish_time(self._packument, package, version)
        source_dir = package_json_path.parent if include_source else None

        return PackageVersionSnapshot(
            package=package,
            version=version,
            published_at=published_at,
            package_json=package_json,
            source_dir=source_dir,
        )


def _find_package_json(raw_root: Path) -> Path:
    """raw_root 아래에서 npm tarball 최상위 규약(".../package/package.json")과
    일치하는 파일을 찾는다. 0개/2개 이상이면 데이터 품질 문제로 보고 에러를 낸다
    (임의로 하나를 고르지 않는다).
    """
    candidates = [p for p in raw_root.rglob("package.json") if p.parent.name == "package"]
    if not candidates:
        raise LoaderError(f"no package.json found under {raw_root} (expected .../package/package.json)")
    if len(candidates) > 1:
        raise LoaderError(f"multiple package.json candidates found under {raw_root}: {candidates}")
    return candidates[0]
