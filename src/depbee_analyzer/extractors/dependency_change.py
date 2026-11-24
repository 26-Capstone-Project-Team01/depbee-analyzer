"""의존성 변경 Feature D: 기존 의존성 버전 범위 변경 수, 전체 의존성 대비 변경 비율 (package.json만).

정의는 docs/x3-features.md 3절. 범위는 기존 newDependencyAdded와 같다(dependencies ∪ optionalDependencies, dev·peer 제외).
선언 문자열만 비교하고 semver 해석이나 registry 조회는 하지 않는다. 기본 실행 목록에는 넣지 않는다.
"""

from __future__ import annotations

from typing import Any

from depbee_analyzer.core.models import PackageVersionSnapshot
from depbee_analyzer.extractors.base import BaseExtractor

FIELDS = ("dependencies", "optionalDependencies")  # 뒤 필드가 이긴다(npm: optional이 같은 이름의 dependencies를 덮는다)
FEATURE_NAMES = ("dependencyRangeChangedCount", "dependencyChangedRatio")


def declared_dependencies(package_json: dict[str, Any]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for field in FIELDS:
        value = package_json.get(field)
        if isinstance(value, dict):  # 객체가 아니면 빈 객체로 본다
            deps.update({str(k): str(v).strip() for k, v in value.items()})
    return deps


def dependency_change_features(old_json: dict[str, Any], new_json: dict[str, Any]) -> dict[str, Any]:
    old, new = declared_dependencies(old_json), declared_dependencies(new_json)
    common = old.keys() & new.keys()
    range_changed = sum(1 for name in common if old[name] != new[name])
    union = old.keys() | new.keys()
    changed = len(new.keys() - old.keys()) + len(old.keys() - new.keys()) + range_changed
    return {
        "dependencyRangeChangedCount": range_changed,
        "dependencyChangedRatio": changed / len(union) if union else None,
    }


class DependencyChangeExtractor(BaseExtractor):
    """`--extractors dependency_change`로 켠다."""

    name = "dependency_change"
    required_data = frozenset({"package_json"})

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        return dependency_change_features(old.package_json, new.package_json)
