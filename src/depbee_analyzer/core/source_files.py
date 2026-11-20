"""snapshot의 source_dir에서 분석 대상 소스 파일을 모으는 공용 유틸리티.

이 모듈은 파일을 **읽기만** 한다. 대상 패키지의 코드를 실행하거나 npm install,
lifecycle script를 돌리지 않는다. required_data에 "source"를 선언한 extractor
(예: obfuscation)가 공통으로 사용한다.

수집 범위를 extractor마다 다르게 정의하면 같은 dataset 안에서 feature의 모집단이
달라지므로, 대상 확장자·제외 디렉터리·상한값은 여기 한 곳에서만 정의한다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from depbee_analyzer.core.errors import ExtractionError
from depbee_analyzer.core.models import PackageVersionSnapshot

#: 분석 대상 확장자. npm 배포 산출물에서 실제로 실행되는 JS 계열만 본다.
#: (.ts 등 소스는 배포본에 포함되더라도 실행되는 산출물이 아니므로 현재는 제외한다.)
SOURCE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs"})

#: 패키지 안에 함께 실려오더라도 대상 패키지 자신의 코드가 아니므로 제외하는 디렉터리.
EXCLUDED_DIR_NAMES = frozenset({"node_modules", ".git"})

#: 파일 하나의 크기 상한. 정상 패키지를 거르려는 필터가 아니라, 비정상적으로 큰
#: 입력으로 메모리를 소진하는 것을 막기 위한 방어선이다.
#: 악성 페이로드는 번들·난독화로 수 MB에 이르는 경우가 흔하다(npm-malware-package-pairs의
#: bun_environment.js는 최대 약 9.7MB). 이 상한이 페이로드보다 작으면 가장 중요한 악성
#: 샘플이 errors.csv로 빠지므로, 알려진 최대 크기보다 충분히 크게 잡는다.
MAX_FILE_BYTES = 64 * 1024 * 1024

#: 한 스냅샷에서 읽을 파일 수 상한. 위와 같은 목적의 방어선이다.
MAX_FILE_COUNT = 5000


@dataclass(frozen=True)
class SourceFile:
    """수집된 소스 파일 한 개의 내용과 메타데이터."""

    #: 패키지 루트 기준 상대 경로 (POSIX 구분자, OS와 무관하게 동일한 값).
    relative_path: str
    size_bytes: int
    text: str

    #: 디코딩에 사용한 인코딩. utf-8로 읽히지 않으면 latin-1로 폴백한다
    #: (latin-1은 모든 바이트를 1:1로 매핑하므로 실패하지 않고, 바이트 단위
    #: 통계를 쓰는 feature가 원본 정보를 잃지 않는다).
    decoded_as: str


@dataclass(frozen=True)
class SourceFileSet:
    """한 버전의 스냅샷에서 수집한 소스 파일 전체."""

    root: Path
    files: tuple[SourceFile, ...]

    def __len__(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(source_file.size_bytes for source_file in self.files)

    def by_relative_path(self) -> dict[str, SourceFile]:
        """상대 경로 → SourceFile 매핑. old/new를 파일 단위로 대응시킬 때 사용한다."""
        return {source_file.relative_path: source_file for source_file in self.files}


def collect_source_files(
    snapshot: PackageVersionSnapshot,
    *,
    extensions: frozenset[str] = SOURCE_EXTENSIONS,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_file_count: int = MAX_FILE_COUNT,
) -> SourceFileSet:
    """snapshot.source_dir 아래의 분석 대상 소스 파일을 모두 읽어 반환한다.

    상한을 넘으면 일부만 읽고 성공한 척하지 않고 ExtractionError를 낸다.
    잘린 파일 집합으로 계산한 feature는 같은 이름의 다른 행과 의미가 달라지므로,
    batch 실행 시 dataset.errors.csv에 남겨 데이터 품질 문제를 드러내는 편이 낫다.

    디렉터리와 파일 이름을 각각 정렬해 깊이 우선으로 내려가므로, 같은 입력에 대해
    파일 순서는 항상 같다.
    """
    if snapshot.source_dir is None:
        raise ExtractionError(
            f"source tree is not loaded for {snapshot.package!r}@{snapshot.version!r}; "
            "the extractor must declare \"source\" in required_data"
        )

    root = snapshot.source_dir
    if not root.is_dir():
        raise ExtractionError(
            f"source_dir {root} for {snapshot.package!r}@{snapshot.version!r} is not a directory"
        )

    files: list[SourceFile] = []
    for path in _walk_source_paths(root, snapshot):
        if path.suffix.lower() not in extensions:
            continue

        if len(files) >= max_file_count:
            raise ExtractionError(
                f"{snapshot.package!r}@{snapshot.version!r} has more than {max_file_count} "
                f"source files under {root}; refusing to analyze a truncated file set"
            )

        relative_path = path.relative_to(root).as_posix()
        files.append(_read_source_file(path, relative_path, max_file_bytes, snapshot))

    return SourceFileSet(root=root, files=tuple(files))


def _walk_source_paths(root: Path, snapshot: PackageVersionSnapshot) -> list[Path]:
    """root 아래의 일반 파일을 결정적 순서로 모은다.

    Path.rglob()을 쓰지 않는 이유가 두 가지 있다.

    1. rglob()은 읽지 못한 디렉터리를 조용히 건너뛴다. Windows의 260자 경로 제한처럼
       환경에 따라 접근이 막히는 경우, 일부 파일이 빠진 채로 feature가 계산되고
       그 사실이 아무 데도 남지 않는다. 여기서는 os.walk의 onerror로 받아 실패시킨다.
    2. rglob()은 제외 대상 디렉터리에도 일단 내려간다. node_modules처럼 파일이 많고
       경로가 깊은 디렉터리는 내려가는 것 자체가 비용이자 위 1번의 원인이 되므로,
       os.walk의 dirnames를 잘라 아예 진입하지 않는다.
    """

    def on_error(error: OSError) -> None:
        raise ExtractionError(
            f"failed to walk the source tree of {snapshot.package!r}@{snapshot.version!r} "
            f"at {error.filename}: {error}"
        ) from error

    paths: list[Path] = []
    for dir_path, dir_names, file_names in os.walk(root, onerror=on_error):
        dir_names[:] = sorted(name for name in dir_names if name not in EXCLUDED_DIR_NAMES)
        current_dir = Path(dir_path)
        for file_name in sorted(file_names):
            path = current_dir / file_name
            # symlink는 내용을 따라가면 같은 파일을 중복 집계하거나 트리 밖을 읽게 되므로 건너뛴다.
            if path.is_symlink() or not path.is_file():
                continue
            paths.append(path)
    return paths


def _read_source_file(
    path: Path,
    relative_path: str,
    max_file_bytes: int,
    snapshot: PackageVersionSnapshot,
) -> SourceFile:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ExtractionError(
            f"failed to read {relative_path} of {snapshot.package!r}@{snapshot.version!r}: {exc}"
        ) from exc

    if len(raw) > max_file_bytes:
        raise ExtractionError(
            f"{relative_path} of {snapshot.package!r}@{snapshot.version!r} is {len(raw)} bytes, "
            f"over the {max_file_bytes} byte limit; refusing to analyze a partial file set"
        )

    try:
        text = raw.decode("utf-8")
        decoded_as = "utf-8"
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        decoded_as = "latin-1"

    return SourceFile(
        relative_path=relative_path,
        size_bytes=len(raw),
        text=text,
        decoded_as=decoded_as,
    )
