from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PackageVersionSnapshot:
    """단일 (package, version)에 대한 npm registry 데이터.

    순수 데이터 컨테이너이며 I/O를 수행하지 않는다. 모든 필드는 loader가 채워서 넘긴다.
    """

    package: str
    version: str
    published_at: datetime
    package_json: dict[str, Any]

    #: 이 버전의 소스 트리 루트. include_source=True로 조회했을 때만 채워진다.
    #: 어느 SnapshotSource를 쓰든 "package.json이 들어있는 패키지 루트"를 가리킨다
    #: (tarball 압축 해제 시 생기는 바깥쪽 "package/" 디렉터리가 아니다).
    #: 따라서 이 값을 기준으로 한 상대 경로는 source 종류와 무관하게 같은 의미를 갖는다.
    source_dir: Path | None = None


@dataclass(frozen=True)
class FeatureRow:
    """등록된 extractor들의 결과를 합친 dataset의 한 행."""

    package: str
    old_version: str
    new_version: str
    features: dict[str, Any]
    label: int

    def to_flat_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "old_version": self.old_version,
            "new_version": self.new_version,
            **self.features,
            "label": self.label,
        }
