from depbee_analyzer.extractors.base import BaseExtractor
from depbee_analyzer.extractors.code_context import CodeContextExtractor
from depbee_analyzer.extractors.obfuscation import ObfuscationExtractor
from depbee_analyzer.extractors.package_json import PackageJsonExtractor

#: 새 extractor가 추가되면 이 dict에 한 줄만 등록하면 된다.
#: --extractors 플래그가 생략되면 이 registry에 등록된 전체가 기본 실행된다.
#: depbee의 내장 분석기도 기본 목록(resolve_extractors(None))을 쓰므로, 여기에 넣으면
#: 제품의 feature 출력(depbee-features-v1)이 바뀐다.
EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {
    "package_json": PackageJsonExtractor,
    "obfuscation": ObfuscationExtractor,
}

#: 이름으로 지정할 때만 실행되는 실험용 extractor. 기본 실행과 제품 출력에는 들어가지 않는다.
#: 예: --extractors package_json,obfuscation,code_context
OPTIONAL_EXTRACTOR_REGISTRY: dict[str, type[BaseExtractor]] = {
    "code_context": CodeContextExtractor,
}

__all__ = ["BaseExtractor", "EXTRACTOR_REGISTRY", "OPTIONAL_EXTRACTOR_REGISTRY"]
