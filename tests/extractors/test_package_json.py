from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from feature_extractor.core.errors import ExtractionError
from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.extractors.package_json import PackageJsonExtractor

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "package_json"


def _load_package_json(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))


def _snapshot(package_json: dict, published_at: datetime) -> PackageVersionSnapshot:
    return PackageVersionSnapshot(
        package=package_json["name"],
        version=package_json["version"],
        published_at=published_at,
        package_json=package_json,
    )


@pytest.fixture
def extractor() -> PackageJsonExtractor:
    return PackageJsonExtractor()


def test_event_stream_style_update_flags_all_true(extractor: PackageJsonExtractor) -> None:
    old_snapshot = _snapshot(
        _load_package_json("event-stream_3.3.5.json"),
        datetime(2018, 9, 1, tzinfo=timezone.utc),
    )
    new_snapshot = _snapshot(
        _load_package_json("event-stream_3.3.6.json"),
        datetime(2018, 9, 2, tzinfo=timezone.utc),
    )

    features = extractor.extract(old_snapshot, new_snapshot)

    assert features["installScriptPresent"] is True
    assert features["installScriptAdded"] is True
    assert features["scriptEntryAdded"] is True
    assert features["newDependencyAdded"] is True
    assert features["newDependencyCount"] == 1
    assert features["updateType"] == "patch"
    assert features["updateInterval"] == timedelta(days=1).total_seconds()


def test_no_change_between_versions_gives_false_flags(extractor: PackageJsonExtractor) -> None:
    package_json_old = {
        "name": "sample-pkg",
        "version": "1.0.0",
        "scripts": {"test": "node test.js"},
        "dependencies": {"lodash": "^4.0.0"},
    }
    package_json_new = {**package_json_old, "version": "1.0.1"}

    old_snapshot = _snapshot(package_json_old, datetime(2024, 1, 1, tzinfo=timezone.utc))
    new_snapshot = _snapshot(package_json_new, datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc))

    features = extractor.extract(old_snapshot, new_snapshot)

    assert features["installScriptPresent"] is False
    assert features["installScriptAdded"] is False
    assert features["scriptEntryAdded"] is False
    assert features["newDependencyAdded"] is False
    assert features["newDependencyCount"] == 0
    assert features["updateType"] == "patch"
    assert features["updateInterval"] == 30.0


def test_optional_dependencies_count_toward_new_dependency(extractor: PackageJsonExtractor) -> None:
    package_json_old = {"name": "sample-pkg", "version": "1.0.0"}
    package_json_new = {
        "name": "sample-pkg",
        "version": "1.0.1",
        "optionalDependencies": {"fsevents": "^2.0.0"},
    }

    old_snapshot = _snapshot(package_json_old, datetime(2024, 1, 1, tzinfo=timezone.utc))
    new_snapshot = _snapshot(package_json_new, datetime(2024, 1, 1, tzinfo=timezone.utc))

    features = extractor.extract(old_snapshot, new_snapshot)

    assert features["newDependencyAdded"] is True
    assert features["newDependencyCount"] == 1


def test_dev_dependencies_are_excluded_from_new_dependency_count(
    extractor: PackageJsonExtractor,
) -> None:
    package_json_old = {"name": "sample-pkg", "version": "1.0.0"}
    package_json_new = {
        "name": "sample-pkg",
        "version": "1.0.1",
        "devDependencies": {"jest": "^29.0.0"},
    }

    old_snapshot = _snapshot(package_json_old, datetime(2024, 1, 1, tzinfo=timezone.utc))
    new_snapshot = _snapshot(package_json_new, datetime(2024, 1, 1, tzinfo=timezone.utc))

    features = extractor.extract(old_snapshot, new_snapshot)

    assert features["newDependencyAdded"] is False
    assert features["newDependencyCount"] == 0


@pytest.mark.parametrize(
    ("old_version", "new_version", "expected_update_type"),
    [
        ("1.2.3", "2.0.0-beta.1", "major"),
        ("1.2.3-beta.1", "1.2.3", "pre-release"),
        ("1.2.3-beta.1", "1.2.3-beta.2", "pre-release"),
        ("1.2.3", "1.3.0", "minor"),
        ("1.2.3", "1.2.4", "patch"),
        ("1.2.3+001", "1.2.3+002", "build"),
    ],
)
def test_update_type_classification(
    extractor: PackageJsonExtractor,
    old_version: str,
    new_version: str,
    expected_update_type: str,
) -> None:
    package_json_old = {"name": "sample-pkg", "version": old_version}
    package_json_new = {"name": "sample-pkg", "version": new_version}

    old_snapshot = _snapshot(package_json_old, datetime(2024, 1, 1, tzinfo=timezone.utc))
    new_snapshot = _snapshot(package_json_new, datetime(2024, 1, 1, tzinfo=timezone.utc))

    features = extractor.extract(old_snapshot, new_snapshot)

    assert features["updateType"] == expected_update_type


def test_identical_versions_raise_extraction_error(extractor: PackageJsonExtractor) -> None:
    package_json = {"name": "sample-pkg", "version": "1.0.0"}
    old_snapshot = _snapshot(package_json, datetime(2024, 1, 1, tzinfo=timezone.utc))
    new_snapshot = _snapshot(dict(package_json), datetime(2024, 1, 1, tzinfo=timezone.utc))

    with pytest.raises(ExtractionError):
        extractor.extract(old_snapshot, new_snapshot)


def test_invalid_semver_string_raises_extraction_error(extractor: PackageJsonExtractor) -> None:
    old_snapshot = _snapshot(
        {"name": "sample-pkg", "version": "not-a-version"},
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    new_snapshot = _snapshot(
        {"name": "sample-pkg", "version": "1.0.0"},
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(ExtractionError):
        extractor.extract(old_snapshot, new_snapshot)
