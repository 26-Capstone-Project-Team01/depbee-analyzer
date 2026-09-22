from __future__ import annotations


class FeatureExtractorError(Exception):
    """batch 실행 시 dataset.errors.csv에 기록되어야 하는 모든 pair 단위 오류의 기반 클래스."""


class LoaderError(FeatureExtractorError):
    """npm registry 조회, tarball 다운로드 등 loader I/O 과정에서 발생한 오류."""


class ExtractionError(FeatureExtractorError):
    """extractor가 feature를 계산하는 중 발생한 오류 (예: 버전 파싱 실패, 동일 버전 비교)."""
