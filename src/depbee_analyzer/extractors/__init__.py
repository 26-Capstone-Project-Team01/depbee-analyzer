from depbee_analyzer.extractors.base import BaseExtractor
from depbee_analyzer.extractors.obfuscation import ObfuscationExtractor
from depbee_analyzer.extractors.package_json import PackageJsonExtractor

#: 새 extractor가 추가되면 이 dict에 한 줄만 등록하면 된다.
#: --extractors 플래그가 생략되면 이 registry에 등록된 전체가 기본 실행된다.
EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {
    "package_json": PackageJsonExtractor,
    "obfuscation": ObfuscationExtractor,
}

__all__ = ["BaseExtractor", "EXTRACTOR_REGISTRY"]
