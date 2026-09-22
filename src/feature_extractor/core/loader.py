from __future__ import annotations

import io
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from feature_extractor.core.errors import LoaderError
from feature_extractor.core.models import PackageVersionSnapshot

REGISTRY_BASE_URL = "https://registry.npmjs.org"
REQUEST_TIMEOUT_SECONDS = 30


def fetch_packument(package: str) -> dict[str, Any]:
    """npm registry에서 전체 packument(모든 버전의 manifest + publish 시각)를 가져온다.

    old/new 두 버전 모두 같은 package에 속하므로, 호출부는 이 결과 하나를
    build_snapshot()에 두 번(old, new) 재사용해 불필요한 중복 요청을 피한다.
    """
    url = f"{REGISTRY_BASE_URL}/{package}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise LoaderError(f"failed to fetch packument for {package!r}: {exc}") from exc

    try:
        return response.json()
    except ValueError as exc:
        raise LoaderError(f"invalid JSON packument for {package!r}: {exc}") from exc


def build_snapshot(
    packument: dict[str, Any],
    package: str,
    version: str,
    *,
    include_source: bool = False,
) -> PackageVersionSnapshot:
    """packument에서 특정 version의 데이터를 뽑아 PackageVersionSnapshot을 만든다.

    include_source=True일 때만 tarball을 내려받는다 (선택된 extractor 중
    required_data에 "source"가 있는 경우에만 pipeline이 True를 넘긴다).
    """
    versions = packument.get("versions", {})
    package_json = versions.get(version)
    if package_json is None:
        raise LoaderError(f"version {version!r} not found for package {package!r}")

    published_at = get_publish_time(packument, package, version)

    source_dir = _download_and_extract_tarball(package, version, package_json) if include_source else None

    return PackageVersionSnapshot(
        package=package,
        version=version,
        published_at=published_at,
        package_json=package_json,
        source_dir=source_dir,
    )


def get_publish_time(packument: dict[str, Any], package: str, version: str) -> datetime:
    """packument의 time 맵에서 특정 version의 publish 시각을 읽는다.

    npm registry는 버전이 unpublish되어 versions[version]이 사라진 뒤에도
    time[version]은 계속 보존하는 것으로 확인되어(2026-09 시점 관찰),
    로컬 archive 기반 snapshot에서도 이 함수로 timestamp를 얻을 수 있다.
    다만 이는 registry의 공식 계약이 아니라 관찰된 동작이므로, 값이 없으면
    임의로 채우지 않고 LoaderError를 그대로 전파한다.
    """
    time_map = packument.get("time", {})
    published_at_raw = time_map.get(version)
    if published_at_raw is None:
        raise LoaderError(f"publish timestamp not found for {package!r}@{version!r}")

    try:
        return datetime.fromisoformat(published_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LoaderError(
            f"invalid publish timestamp {published_at_raw!r} for {package!r}@{version!r}: {exc}"
        ) from exc


def _download_and_extract_tarball(package: str, version: str, package_json: dict[str, Any]) -> Path:
    tarball_url = package_json.get("dist", {}).get("tarball")
    if not tarball_url:
        raise LoaderError(f"tarball url missing from dist for {package!r}@{version!r}")

    try:
        response = requests.get(tarball_url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise LoaderError(f"failed to download tarball for {package!r}@{version!r}: {exc}") from exc

    extract_dir = Path(tempfile.mkdtemp(prefix="feature_extractor_src_"))
    try:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            # 외부(신뢰할 수 없는) tarball이므로 path traversal 방지를 위해 "data" filter로 추출한다.
            tar.extractall(extract_dir, filter="data")
    except tarfile.TarError as exc:
        raise LoaderError(f"failed to extract tarball for {package!r}@{version!r}: {exc}") from exc

    return extract_dir
