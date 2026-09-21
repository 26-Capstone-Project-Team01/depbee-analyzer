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

    time_map = packument.get("time", {})
    published_at_raw = time_map.get(version)
    if published_at_raw is None:
        raise LoaderError(f"publish timestamp not found for {package!r}@{version!r}")

    try:
        published_at = datetime.fromisoformat(published_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LoaderError(
            f"invalid publish timestamp {published_at_raw!r} for {package!r}@{version!r}: {exc}"
        ) from exc

    source_dir = _download_and_extract_tarball(package, version, package_json) if include_source else None

    return PackageVersionSnapshot(
        package=package,
        version=version,
        published_at=published_at,
        package_json=package_json,
        source_dir=source_dir,
    )


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
