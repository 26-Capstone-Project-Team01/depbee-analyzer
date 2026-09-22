from __future__ import annotations

import io
import tarfile
import time
from unittest.mock import Mock, patch

import pytest
import requests

from feature_extractor.core.errors import LoaderError
from feature_extractor.core.loader import build_snapshot, fetch_packument

SAMPLE_PACKUMENT = {
    "name": "sample-pkg",
    "versions": {
        "1.0.0": {"name": "sample-pkg", "version": "1.0.0"},
    },
    "time": {
        "1.0.0": "2024-01-01T00:00:00.000Z",
    },
}


def _mock_response(json_data: dict, status_ok: bool = True) -> Mock:
    response = Mock()
    response.json.return_value = json_data
    if status_ok:
        response.raise_for_status.return_value = None
    else:
        response.raise_for_status.side_effect = requests.HTTPError("boom")
    return response


@patch("feature_extractor.core.loader.requests.get")
def test_fetch_packument_success(mock_get: Mock) -> None:
    mock_get.return_value = _mock_response(SAMPLE_PACKUMENT)

    result = fetch_packument("sample-pkg")

    assert result == SAMPLE_PACKUMENT
    mock_get.assert_called_once()
    assert "sample-pkg" in mock_get.call_args.args[0]


@patch("feature_extractor.core.loader.requests.get")
def test_fetch_packument_http_error_raises_loader_error(mock_get: Mock) -> None:
    mock_get.return_value = _mock_response({}, status_ok=False)

    with pytest.raises(LoaderError):
        fetch_packument("sample-pkg")


@patch("feature_extractor.core.loader.requests.get")
def test_fetch_packument_network_error_raises_loader_error(mock_get: Mock) -> None:
    mock_get.side_effect = requests.ConnectionError("no network")

    with pytest.raises(LoaderError):
        fetch_packument("sample-pkg")


def test_build_snapshot_success() -> None:
    snapshot = build_snapshot(SAMPLE_PACKUMENT, "sample-pkg", "1.0.0")

    assert snapshot.package == "sample-pkg"
    assert snapshot.version == "1.0.0"
    assert snapshot.package_json == {"name": "sample-pkg", "version": "1.0.0"}
    assert snapshot.published_at.year == 2024
    assert snapshot.source_dir is None


def test_build_snapshot_missing_version_raises_loader_error() -> None:
    with pytest.raises(LoaderError):
        build_snapshot(SAMPLE_PACKUMENT, "sample-pkg", "9.9.9")


def test_build_snapshot_missing_timestamp_raises_loader_error() -> None:
    packument = {
        "versions": {"1.0.0": {"name": "sample-pkg", "version": "1.0.0"}},
        "time": {},
    }

    with pytest.raises(LoaderError):
        build_snapshot(packument, "sample-pkg", "1.0.0")


TARBALL_PACKUMENT = {
    "versions": {
        "1.0.0": {
            "name": "sample-pkg",
            "version": "1.0.0",
            "dist": {"tarball": "https://registry.npmjs.org/sample-pkg/-/sample-pkg-1.0.0.tgz"},
        },
    },
    "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
}


def _tarball_bytes(members: dict[str, bytes]) -> bytes:
    """합성 npm tarball(.tgz)을 메모리에서 만든다. 네트워크에 접근하지 않는다."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _mock_tarball_response(tarball: bytes) -> Mock:
    response = Mock()
    response.content = tarball
    response.raise_for_status.return_value = None
    return response


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_strips_the_tarball_top_level_dir(mock_get: Mock) -> None:
    """source_dir은 압축 해제 루트가 아니라 package.json이 있는 패키지 루트여야 한다.

    LocalArchiveSnapshotSource가 주는 source_dir과 의미를 맞추기 위한 규약이며,
    그래야 두 source에서 뽑은 상대 경로 기반 feature가 같은 의미를 갖는다.
    """
    mock_get.return_value = _mock_tarball_response(
        _tarball_bytes(
            {
                "package/package.json": b'{"name": "sample-pkg", "version": "1.0.0"}',
                "package/index.js": b"module.exports = 1;\n",
            }
        )
    )

    snapshot = build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0", include_source=True)

    assert snapshot.source_dir is not None
    assert (snapshot.source_dir / "package.json").is_file()
    assert (snapshot.source_dir / "index.js").is_file()
    assert snapshot.source_dir.name == "package"


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_accepts_non_package_top_level_dir(mock_get: Mock) -> None:
    """최상위 디렉터리 이름이 "package"가 아닌 tarball도 패키지 루트를 찾아야 한다."""
    mock_get.return_value = _mock_tarball_response(
        _tarball_bytes(
            {
                "sample-pkg/package.json": b'{"name": "sample-pkg", "version": "1.0.0"}',
                "sample-pkg/index.js": b"module.exports = 1;\n",
            }
        )
    )

    snapshot = build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0", include_source=True)

    assert snapshot.source_dir is not None
    assert (snapshot.source_dir / "package.json").is_file()


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_without_package_json_raises_loader_error(mock_get: Mock) -> None:
    mock_get.return_value = _mock_tarball_response(_tarball_bytes({"docs/readme.md": b"hi"}))

    with pytest.raises(LoaderError):
        build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0", include_source=True)


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_missing_tarball_url_raises_loader_error(mock_get: Mock) -> None:
    packument = {
        "versions": {"1.0.0": {"name": "sample-pkg", "version": "1.0.0"}},
        "time": {"1.0.0": "2024-01-01T00:00:00.000Z"},
    }

    with pytest.raises(LoaderError):
        build_snapshot(packument, "sample-pkg", "1.0.0", include_source=True)

    mock_get.assert_not_called()


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_download_failure_raises_loader_error(mock_get: Mock) -> None:
    mock_get.side_effect = requests.ConnectionError("no network")

    with pytest.raises(LoaderError):
        build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0", include_source=True)


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_with_source_corrupt_tarball_raises_loader_error(mock_get: Mock) -> None:
    mock_get.return_value = _mock_tarball_response(b"not a gzip tarball")

    with pytest.raises(LoaderError):
        build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0", include_source=True)


@patch("feature_extractor.core.loader.requests.get")
def test_build_snapshot_without_source_does_not_download_tarball(mock_get: Mock) -> None:
    snapshot = build_snapshot(TARBALL_PACKUMENT, "sample-pkg", "1.0.0")

    assert snapshot.source_dir is None
    mock_get.assert_not_called()
