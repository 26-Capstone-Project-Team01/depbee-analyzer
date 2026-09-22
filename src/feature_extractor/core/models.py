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
