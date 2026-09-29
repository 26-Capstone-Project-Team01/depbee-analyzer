from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.core.source_files import SourceFile
from feature_extractor.extractors import EXTRACTOR_REGISTRY
from feature_extractor.extractors.obfuscation import (
    METRICS,
    ObfuscationExtractor,
    aggregate,
    file_metrics,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "obfuscation"
EXPECTED_COLUMNS = ["obfChangedFileCount"] + [
    f"obf{metric.name}{suffix}" for metric in METRICS for suffix in ("New", "Change", "ChangedCode")
]


def _snapshot(version: str, source_dir: Path) -> PackageVersionSnapshot:
    return PackageVersionSnapshot(
        package="sample-pkg",
        version=version,
        published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        package_json={"name": "sample-pkg", "version": version},
        source_dir=source_dir,
    )


def _write(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def extractor() -> ObfuscationExtractor:
    return ObfuscationExtractor()


def test_declares_source_so_pipeline_downloads_the_tarball() -> None:
    assert "source" in ObfuscationExtractor.required_data


def test_is_registered() -> None:
    assert EXTRACTOR_REGISTRY["obfuscation"] is ObfuscationExtractor


def test_emits_a_fixed_set_of_columns_in_a_fixed_order(extractor: ObfuscationExtractor) -> None:
    features = extractor.extract(
        _snapshot("1.0.0", FIXTURES_DIR / "clean"), _snapshot("1.0.1", FIXTURES_DIR / "obfuscated")
    )

    assert list(features) == EXPECTED_COLUMNS


def test_obfuscated_update_is_reflected_in_new_change_and_changed_code(extractor: ObfuscationExtractor) -> None:
    features = extractor.extract(
        _snapshot("1.0.0", FIXTURES_DIR / "clean"), _snapshot("1.0.1", FIXTURES_DIR / "obfuscated")
    )

    # index.js만 바뀌었고 lib/format.js는 그대로다
    assert features["obfChangedFileCount"] == 1
    assert features["obfHexIdentRatioChangedCode"] > 0.5
    assert features["obfHexIdentRatioNew"] == features["obfHexIdentRatioChangedCode"]
    assert features["obfHexIdentRatioChange"] > 0.5
    assert features["obfHexNumberRatioChangedCode"] == 1.0
    assert features["obfBracketAccessRatioChangedCode"] == 1.0
    assert features["obfEscapeDensityChangedCode"] > 0.1
    assert features["obfPackerSignatureChangedCode"] == 0.0


def test_unchanged_update_has_missing_changed_code_values_not_zero(
    extractor: ObfuscationExtractor, tmp_path: Path
) -> None:
    files = {"index.js": "module.exports = function add(a, b) { return a + b; };\n"}
    old = _write(tmp_path / "old", files)
    new = _write(tmp_path / "new", files)

    features = extractor.extract(_snapshot("1.0.0", old), _snapshot("1.0.1", new))

    assert features["obfChangedFileCount"] == 0
    for metric in METRICS:
        assert features[f"obf{metric.name}ChangedCode"] is None
        assert features[f"obf{metric.name}New"] is not None
        assert features[f"obf{metric.name}Change"] == 0.0


def test_package_without_javascript_yields_missing_values_instead_of_error(
    extractor: ObfuscationExtractor, tmp_path: Path
) -> None:
    old = _write(tmp_path / "old", {"README.md": "docs", "index.d.ts": "export {};"})
    new = _write(tmp_path / "new", {"README.md": "docs v2", "index.d.ts": "export {};"})

    features = extractor.extract(_snapshot("1.0.0", old), _snapshot("1.0.1", new))

    assert features["obfChangedFileCount"] == 0
    assert all(value is None for key, value in features.items() if key != "obfChangedFileCount")


def test_added_file_counts_as_changed_code(extractor: ObfuscationExtractor, tmp_path: Path) -> None:
    old = _write(tmp_path / "old", {"index.js": "module.exports = 1;\n"})
    new = _write(
        tmp_path / "new",
        {"index.js": "module.exports = 1;\n", "setup.js": "var _0x1a2b=['a'];console[_0x3c4d(0x0)]();\n"},
    )

    features = extractor.extract(_snapshot("1.0.0", old), _snapshot("1.0.1", new))

    assert features["obfChangedFileCount"] == 1
    assert features["obfHexIdentRatioChangedCode"] > 0


def test_typescript_enum_members_are_not_counted_as_bracket_access() -> None:
    compiled_enum = (
        "export var LogLevel;\n"
        "(function (LogLevel) {\n"
        '    LogLevel["ERROR"] = "error";\n'
        '    LogLevel["WARN"] = "warn";\n'
        '    LogLevel["INFO"] = "info";\n'
        "})(LogLevel || (LogLevel = {}));\n"
    )
    commonjs_enum = (
        "var Mode;\n"
        "(function (Mode) {\n"
        '    Mode[Mode["Fast"] = 0] = "Fast";\n'
        "})(Mode || (exports.Mode = Mode = {}));\n"
    )

    assert file_metrics(compiled_enum)["BracketAccessRatio"] == 0.0
    assert file_metrics(commonjs_enum)["BracketAccessRatio"] == 0.0
    assert file_metrics("var x = obj['secret'];")["BracketAccessRatio"] == 1.0


def test_packer_signature_is_detected_anywhere_in_the_file() -> None:
    packed = "var a = 1;\neval(function(p,a,c,k,e,d){return p}('0',62,1,'x'.split('|'),0,{}))"

    assert file_metrics(packed)["PackerSignature"] == 1.0
    assert file_metrics("eval(code)")["PackerSignature"] == 0.0


def test_strings_and_comments_do_not_count_as_identifiers() -> None:
    metrics = file_metrics("// _0xabc _0xdef\nvar name = '_0x123 _0x456';\n")

    assert metrics["HexIdentRatio"] == 0.0


def _source_file(path: str, text: str) -> SourceFile:
    return SourceFile(relative_path=path, size_bytes=len(text), text=text, decoded_as="utf-8")


def test_tiny_files_do_not_drive_lower_is_obfuscated_metrics() -> None:
    """한 줄짜리 파일의 공백 비율이 패키지 전체의 값이 되면 안 된다."""
    tiny = _source_file("tiny.js", "module.exports=1;")
    readable = _source_file("index.js", "function add(first, second) {\n    return first + second;\n}\n" * 40)
    files = [tiny, readable]

    result = aggregate(files, {f.relative_path: file_metrics(f.text) for f in files})

    assert result is not None
    assert result["WhitespaceRatio"] == file_metrics(readable.text)["WhitespaceRatio"]
    assert result["WhitespaceRatio"] > 0.1


def test_aggregate_uses_the_most_obfuscated_file_for_higher_is_obfuscated_metrics() -> None:
    clean = _source_file("a.js", "var total = price * count;\n" * 50)
    obfuscated = _source_file("b.js", "var _0x1f2a=_0x3b4c(0x1)+_0x5d6e[0x2];\n")
    files = [clean, obfuscated]

    result = aggregate(files, {f.relative_path: file_metrics(f.text) for f in files})

    assert result is not None
    assert result["HexIdentRatio"] == file_metrics(obfuscated.text)["HexIdentRatio"]


def test_aggregate_of_no_files_is_none() -> None:
    assert aggregate([], {}) is None


def test_lower_is_obfuscated_metrics_are_none_when_there_is_nothing_to_measure() -> None:
    """식별자가 없는 파일의 평균 식별자 길이는 0이 아니라 계산할 수 없는 값이다."""
    numbers_only = file_metrics("[" + ",".join(str(i) for i in range(50)) + "]")
    empty = file_metrics("")

    assert numbers_only["MeanIdentLength"] is None
    assert numbers_only["WhitespaceRatio"] == 0.0
    assert empty["MeanIdentLength"] is None
    assert empty["WhitespaceRatio"] is None
    # 클수록 난독화인 지표는 그대로 0.0이다.
    assert empty["HexIdentRatio"] == 0.0
    assert empty["HexNumberRatio"] == 0.0


def test_file_without_identifiers_does_not_drive_mean_ident_length_to_zero() -> None:
    data = _source_file("data.js", "[" + ",".join(str(i) for i in range(400)) + "]")
    readable = _source_file("index.js", "function add(first, second) {\n    return first + second;\n}\n" * 40)
    files = [data, readable]
    assert data.size_bytes >= 1024

    result = aggregate(files, {f.relative_path: file_metrics(f.text) for f in files})

    assert result is not None
    assert result["MeanIdentLength"] == file_metrics(readable.text)["MeanIdentLength"]
    assert result["MeanIdentLength"] > 3


def test_small_files_are_used_when_the_only_large_file_has_no_value() -> None:
    data = _source_file("data.js", "[" + ",".join(str(i) for i in range(400)) + "]")
    small = _source_file("index.js", "var x = require('./data');\nmodule.exports = x;\n")
    files = [data, small]

    result = aggregate(files, {f.relative_path: file_metrics(f.text) for f in files})

    assert result is not None
    assert result["MeanIdentLength"] == file_metrics(small.text)["MeanIdentLength"]


def test_package_where_no_file_has_identifiers_has_missing_mean_ident_length(
    extractor: ObfuscationExtractor, tmp_path: Path
) -> None:
    old = _write(tmp_path / "old", {"index.js": "module.exports = 1;\n"})
    new = _write(tmp_path / "new", {"index.js": "[1, 2, 3]\n"})

    features = extractor.extract(_snapshot("1.0.0", old), _snapshot("1.0.1", new))

    assert features["obfMeanIdentLengthNew"] is None
    assert features["obfMeanIdentLengthChange"] is None
    assert features["obfMeanIdentLengthChangedCode"] is None
    assert features["obfWhitespaceRatioNew"] is not None
    assert features["obfHexIdentRatioNew"] == 0.0
