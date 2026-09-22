from __future__ import annotations

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
