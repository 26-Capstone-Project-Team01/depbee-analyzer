"""코드 난독화 feature extractor.

지표 선정과 평가 근거는 docs/obfuscation-features.md에 있다. 요약하면:

- 대상 패키지의 코드는 읽기만 한다. 실행하거나 npm 명령을 돌리지 않는다.
- 지표는 정규식과 문자 통계로 계산한다. JS 파서나 난독화 판별 라이브러리는 쓰지 않는다
  (실제 난독화 도구 출력으로 비교한 결과 직접 구현이 더 넓게 잡고 실패가 조용히 묻히지 않았다).
- 팀 설계(방안 1+2)에 맞춰 지표마다 세 가지 값을 낸다.
    - ``...New``: 새 버전 전체
    - ``...Change``: 새 버전 전체 값 - 이전 버전 전체 값
    - ``...ChangedCode``: 이번 업데이트에서 추가·수정된 파일만
- 값을 계산할 파일이 없으면 0으로 채우지 않고 None으로 둔다(CSV에서는 빈 칸,
  LightGBM에서는 결측). ``obfChangedFileCount``가 0이면 ``...ChangedCode``가 모두 None이다.
- 작을수록 난독화인 지표(MeanIdentLength, WhitespaceRatio)는 파일에서 값을 정의할 수 없으면
  (식별자가 없는 파일, 빈 파일) 0.0이 아니라 None을 내고 집계에서 뺀다. 0.0은 이 지표에서
  "가장 난독화됨"이라는 극단값이라, 주석만 있는 파일 하나가 패키지 값을 정해 버리기 때문이다.
  클수록 난독화인 지표는 0.0이 "난독화 흔적 없음"이라 최대값 집계에 해가 없으므로 그대로 둔다.
- packer(``eval(function(p,a,c,k,e,d)``) 흔적 지표는 뺐다. 실제 dataset 3,147쌍과 archive JS
  60,421개에서 한 번도 나오지 않아 정보가 없었다. 근거와 복원 방법은 설계 문서에 있다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from feature_extractor.core.models import PackageVersionSnapshot
from feature_extractor.core.source_files import SourceFile, SourceFileSet, collect_source_files
from feature_extractor.extractors.base import BaseExtractor

# 주석, 문자열, 템플릿 리터럴. 선형 시간에 매칭되도록 작성했다(정규식 리터럴은 구분하지 못한다).
_LEX = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r"|'(?:[^'\\\n]|\\.)*'"
    r'|"(?:[^"\\\n]|\\.)*"'
    r"|`(?:[^`\\]|\\.)*`",
    re.S,
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_HEX_IDENT = re.compile(r"_0x[0-9a-fA-F]{3,}")
_NUMBER = re.compile(r"\b(?:0x[0-9a-fA-F]+|\d+)\b")
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}")
# 멤버 접근 중 키가 문자열 리터럴이거나 _0x 계열 함수 호출인 것: obj['x'], obj['\x78'], obj[_0xab(0x1)]
_BRACKET_ACCESS = re.compile(r"[\w$)\]]\s*\[\s*(?:'|\"|_0x[0-9a-fA-F]+\s*\()")
_DOT_ACCESS = re.compile(r"\.[A-Za-z_$]")
# TypeScript enum을 컴파일한 코드의 꼬리: })(E || (E = {})) 또는 })(E || (exports.E = E = {}))
# 이 enum의 멤버 정의 E["A"] = "a"는 난독화가 아니므로 대괄호 접근 집계에서 뺀다.
_TS_ENUM_TAIL = re.compile(
    r"\(\s*([A-Za-z_$][\w$]*)\s*\|\|\s*\(\s*(?:exports\.[\w$]+\s*=\s*)*(?:\1\s*=\s*)?\{\s*\}\s*\)\s*\)"
)

_JS_KEYWORDS = frozenset(
    "break case catch class const continue debugger default delete do else export extends "
    "false finally for function if import in instanceof let new null return super switch this "
    "throw true try typeof var void while with yield async await of undefined".split()
)

#: 작을수록 난독화에 가까운 지표는 아주 작은 파일에서 극단값이 나오기 쉬워(예: 한 줄짜리
#: 파일의 공백 비율) 이 크기 이상의 파일만 본다. 해당하는 파일이 없으면 전체를 본다.
MIN_BYTES_FOR_LOWER_IS_OBFUSCATED = 1024


@dataclass(frozen=True)
class _Metric:
    name: str
    #: +1이면 클수록, -1이면 작을수록 난독화에 가깝다. 패키지 단위 집계 방향을 정한다.
    direction: int
    #: 계산할 대상이 없으면 None. 클수록 난독화인 지표는 None 대신 0.0을 낸다(최대값 집계에서
    #: 0은 다른 파일의 값을 가리지 않고, 이전 버전에 대상이 없던 경우의 Change 신호를 살린다).
    compute: Callable[["_FileStats"], float | None]


@dataclass(frozen=True)
class _FileStats:
    """파일 하나에서 지표 계산에 필요한 중간 결과."""

    text: str
    code: str  # 주석과 문자열을 공백으로 바꾼 코드
    identifiers: tuple[str, ...]
    numbers: tuple[str, ...]


def _file_stats(text: str) -> _FileStats:
    parts: list[str] = []
    last = 0
    for match in _LEX.finditer(text):
        parts.append(text[last : match.start()])
        parts.append(" ")
        last = match.end()
    parts.append(text[last:])
    code = "".join(parts)
    identifiers = tuple(t for t in _IDENT.findall(code) if t not in _JS_KEYWORDS)
    return _FileStats(text=text, code=code, identifiers=identifiers, numbers=tuple(_NUMBER.findall(code)))


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _hex_ident_ratio(s: _FileStats) -> float:
    return _ratio(sum(1 for t in s.identifiers if _HEX_IDENT.fullmatch(t)), len(s.identifiers))


def _hex_number_ratio(s: _FileStats) -> float:
    return _ratio(sum(1 for n in s.numbers if n.startswith("0x")), len(s.numbers))


def _bracket_access_ratio(s: _FileStats) -> float:
    bracket = len(_BRACKET_ACCESS.findall(s.text))
    for enum_name in set(_TS_ENUM_TAIL.findall(s.text)):
        bracket -= len(re.findall(rf"(?<![\w$]){re.escape(enum_name)}\s*\[\s*['\"]", s.text))
    bracket = max(bracket, 0)
    return _ratio(bracket, bracket + len(_DOT_ACCESS.findall(s.code)))


def _escape_density(s: _FileStats) -> float:
    escaped_chars = len(_HEX_ESCAPE.findall(s.text)) * 4 + len(_UNICODE_ESCAPE.findall(s.text)) * 6
    return _ratio(escaped_chars, len(s.text))


def _short_ident_ratio(s: _FileStats) -> float:
    return _ratio(sum(1 for t in s.identifiers if len(t) <= 2), len(s.identifiers))


def _mean_ident_length(s: _FileStats) -> float | None:
    if not s.identifiers:
        return None
    return sum(len(t) for t in s.identifiers) / len(s.identifiers)


def _whitespace_ratio(s: _FileStats) -> float | None:
    if not s.text:
        return None
    return sum(1 for c in s.text if c.isspace()) / len(s.text)


#: dataset 컬럼 이름은 obf + 지표 이름 + New/Change/ChangedCode 로 만든다.
METRICS: tuple[_Metric, ...] = (
    _Metric("HexIdentRatio", +1, _hex_ident_ratio),
    _Metric("HexNumberRatio", +1, _hex_number_ratio),
    _Metric("BracketAccessRatio", +1, _bracket_access_ratio),
    _Metric("EscapeDensity", +1, _escape_density),
    _Metric("ShortIdentRatio", +1, _short_ident_ratio),
    _Metric("MeanIdentLength", -1, _mean_ident_length),
    _Metric("WhitespaceRatio", -1, _whitespace_ratio),
)


def file_metrics(text: str) -> dict[str, float | None]:
    """파일 하나의 난독화 지표. 정의할 수 없는 지표는 None이다."""
    stats = _file_stats(text)
    return {metric.name: metric.compute(stats) for metric in METRICS}


def aggregate(
    files: list[SourceFile], metrics_by_path: dict[str, dict[str, float | None]]
) -> dict[str, float | None] | None:
    """여러 파일의 지표를 패키지 단위 하나로 모은다. 파일이 없으면 None.

    파일 하나만 난독화된 경우에도 신호가 희석되지 않도록 난독화 쪽 극값을 쓴다
    (방향 +1은 최대값, -1은 1KB 이상 파일의 최소값). 값이 None인 파일은 그 지표의
    집계에서 빼고, 남는 파일이 없으면 그 지표는 None이다.
    """
    if not files:
        return None
    result: dict[str, float | None] = {}
    for metric in METRICS:
        valued = [f for f in files if metrics_by_path[f.relative_path][metric.name] is not None]
        if metric.direction < 0:
            valued = [f for f in valued if f.size_bytes >= MIN_BYTES_FOR_LOWER_IS_OBFUSCATED] or valued
        values = [metrics_by_path[f.relative_path][metric.name] for f in valued]
        if not values:
            result[metric.name] = None
        else:
            result[metric.name] = max(values) if metric.direction > 0 else min(values)
    return result


def changed_files(old: SourceFileSet, new: SourceFileSet) -> list[SourceFile]:
    """new에서 추가되었거나 내용이 바뀐 파일."""
    old_by_path = old.by_relative_path()
    return [f for f in new.files if f.relative_path not in old_by_path or old_by_path[f.relative_path].text != f.text]


class ObfuscationExtractor(BaseExtractor):
    name = "obfuscation"
    required_data = frozenset({"source"})

    def extract(self, old: PackageVersionSnapshot, new: PackageVersionSnapshot) -> dict[str, Any]:
        old_files = collect_source_files(old)
        new_files = collect_source_files(new)

        old_metrics = {f.relative_path: file_metrics(f.text) for f in old_files.files}
        # 같은 내용의 파일은 old에서 계산한 값을 재사용한다(큰 패키지에서 대부분의 파일이 그대로다).
        old_by_path = old_files.by_relative_path()
        new_metrics = {
            f.relative_path: (
                old_metrics[f.relative_path]
                if f.relative_path in old_by_path and old_by_path[f.relative_path].text == f.text
                else file_metrics(f.text)
            )
            for f in new_files.files
        }

        changed = changed_files(old_files, new_files)
        new_agg = aggregate(list(new_files.files), new_metrics)
        old_agg = aggregate(list(old_files.files), old_metrics)
        changed_agg = aggregate(changed, new_metrics)

        features: dict[str, Any] = {"obfChangedFileCount": len(changed)}
        for metric in METRICS:
            new_value = new_agg[metric.name] if new_agg else None
            old_value = old_agg[metric.name] if old_agg else None
            features[f"obf{metric.name}New"] = new_value
            features[f"obf{metric.name}Change"] = (
                new_value - old_value if new_value is not None and old_value is not None else None
            )
            features[f"obf{metric.name}ChangedCode"] = changed_agg[metric.name] if changed_agg else None
        return features
