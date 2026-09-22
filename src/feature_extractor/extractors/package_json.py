from __future__ import annotations

from typing import Any

import semver

from feature_extractor.core.errors import ExtractionError
from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.extractors.base import BaseExtractor

#: npm lifecycle install 관련 훅 전체 (공급망 공격 탐지 맥락에서 흔히 쓰이는 진입점).
INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")

#: 신규 dependency 판정 범위. devDependencies는 배포 산출물 실행에 영향을 주지 않으므로 제외.
DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies")

#: updateType 판정 시 비교할 semver 구성요소와, dataset에 기록할 label의 매핑 (상위 → 하위 순서).
#: major/minor/patch는 semver의 precedence 순서와 같고, pre-release/build는
#: precedence 비교에는 쓰이지 않지만 버전 문법상 그 다음 위치이므로 같은 순서로 마지막에 확인한다.
#: 키는 semver.Version의 속성명(하이픈 불가), 값은 dataset에 기록할 label이다.
_UPDATE_TYPE_LABELS = {
    "major": "major",
    "minor": "minor",
    "patch": "patch",
    "prerelease": "pre-release",
    "build": "build",
}


class PackageJsonExtractor(BaseExtractor):
    name = "package_json"
    required_data = frozenset({"package_json"})

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        old_scripts = _script_keys(old.package_json)
        new_scripts = _script_keys(new.package_json)
        old_install_scripts = old_scripts & set(INSTALL_SCRIPT_KEYS)
        new_install_scripts = new_scripts & set(INSTALL_SCRIPT_KEYS)

        old_dependencies = _dependency_names(old.package_json)
        new_dependencies = _dependency_names(new.package_json)
        added_dependencies = new_dependencies - old_dependencies

        return {
            "installScriptPresent": bool(new_install_scripts),
            "installScriptAdded": bool(new_install_scripts - old_install_scripts),
            "scriptEntryAdded": bool(new_scripts - old_scripts),
            "newDependencyAdded": bool(added_dependencies),
            "newDependencyCount": len(added_dependencies),
            "updateType": _classify_update_type(old.version, new.version),
            "updateInterval": (new.published_at - old.published_at).total_seconds(),
        }


def _script_keys(package_json: dict[str, Any]) -> set[str]:
    return set(package_json.get("scripts") or {})


def _dependency_names(package_json: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for field in DEPENDENCY_FIELDS:
        names.update((package_json.get(field) or {}).keys())
    return names


def _classify_update_type(old_version: str, new_version: str) -> str:
    """major > minor > patch > pre-release > build 순으로 비교해 처음 달라지는 구성요소를 반환한다.

    old_version == new_version이거나 semver로 파싱할 수 없는 버전 문자열이면
    임의의 기본값을 반환하지 않고 ExtractionError를 raise한다 (batch 실행 시
    dataset.errors.csv에 기록되어 데이터 품질 문제가 조용히 묻히지 않도록 한다).
    """
    if old_version == new_version:
        raise ExtractionError(
            f"old_version and new_version are identical ({old_version!r}); "
            "cannot classify an update between identical versions"
        )

    try:
        old_semver = semver.Version.parse(old_version)
        new_semver = semver.Version.parse(new_version)
    except ValueError as exc:
        raise ExtractionError(
            f"failed to parse semver version(s): old={old_version!r}, new={new_version!r}: {exc}"
        ) from exc

    for attribute, label in _UPDATE_TYPE_LABELS.items():
        if getattr(old_semver, attribute) != getattr(new_semver, attribute):
            return label

    raise ExtractionError(
        f"old_version and new_version parse to the same semantic version "
        f"(old={old_version!r}, new={new_version!r}) despite differing strings"
    )
