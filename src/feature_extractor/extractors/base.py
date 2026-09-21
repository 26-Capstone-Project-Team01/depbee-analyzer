from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from feature_extractor.core.models import PackageVersionSnapshot


class BaseExtractor(ABC):
    """모든 extractor가 구현해야 하는 최소 인터페이스."""

    name: str

    #: 이 extractor가 필요로 하는 데이터 종류. 현재 값은 "package_json"(기본),
    #: 소스 코드 분석이 필요한 extractor(예: obfuscation)는 "source"를 추가한다.
    #: pipeline이 선택된 extractor들의 required_data 합집합을 보고 loader 호출
    #: 여부(tarball 다운로드 등)를 자동으로 결정하므로, 사용자가 직접 선택할 필요는 없다.
    required_data: frozenset[str] = frozenset({"package_json"})

    @abstractmethod
    def extract(
        self, old: PackageVersionSnapshot, new: PackageVersionSnapshot
    ) -> dict[str, Any]:
        """old/new snapshot으로부터 feature dict를 계산한다. 네트워크 호출은 하지 않는다."""
        raise NotImplementedError
