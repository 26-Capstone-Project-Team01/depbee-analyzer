from __future__ import annotations

import argparse
import sys
from pathlib import Path

from depbee_analyzer.core.errors import FeatureExtractorError
from depbee_analyzer.core.local_dataset import run_local_archive_batch
from depbee_analyzer.core.manifest import run_manifest_batch
from depbee_analyzer.core.pipeline import build_row, resolve_extractors, run_batch


#: batch 명령의 입력·출력 경로 문제로 발생하는 예외. 파일이 없거나(FileNotFoundError),
#: 디렉터리와 파일을 혼동했거나(IsADirectoryError/NotADirectoryError, Windows에서는
#: 디렉터리를 파일로 열면 PermissionError), 쓰기 권한이 없는 경우다.
#: pair 단위 추출 실패(FeatureExtractorError)는 batch 안에서 errors.csv로 가므로 여기 해당하지 않는다.
_PATH_ERRORS = (FileNotFoundError, IsADirectoryError, NotADirectoryError, PermissionError)

#: 인자로 받은 경로가 잘못된 경우의 종료 코드. argparse가 잘못된 인자에 쓰는 값과 같다.
EXIT_INVALID_INPUT = 2


def _split_extractor_names(value: str) -> list[str]:
    return [name.strip() for name in value.split(",") if name.strip()]


def _add_extractors_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--extractors",
        type=_split_extractor_names,
        default=None,
        metavar="NAME[,NAME...]",
        help=(
            "쉼표로 구분된 extractor 이름 목록. 생략하면 등록된 모든 extractor를 실행한다. "
            "extractor별로 dataset을 따로 만들 때(예: obfuscation), 소스 다운로드가 필요 없는 "
            "extractor만 돌릴 때(예: package_json), 디버깅할 때 쓴다"
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depbee-analyzer",
        description=(
            "npm package.json / obfuscation feature 추출 도구. "
            "개발·dataset 생성용이며 최종 사용자 CLI는 depbee repo에 있다."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    single = subparsers.add_parser(
        "single", help="단일 package pair에 대해 feature를 추출해 출력한다 (테스트/디버깅용)"
    )
    single.add_argument("--package", required=True)
    single.add_argument("--old", required=True, dest="old_version")
    single.add_argument("--new", required=True, dest="new_version")
    single.add_argument("--label", required=True, type=int)
    _add_extractors_argument(single)

    batch = subparsers.add_parser(
        "batch", help="pairs.csv를 읽어 dataset.csv를 생성한다 (dataset 생성용)"
    )
    batch.add_argument(
        "--pairs-file",
        required=True,
        type=Path,
        help="package,old_version,new_version,label 컬럼을 가진 CSV 경로 "
        "(예: npm-malware-package-pairs repo 안의 파일)",
    )
    batch.add_argument("--output", required=True, type=Path, dest="output_csv_path")
    batch.add_argument(
        "--errors-output",
        type=Path,
        dest="errors_csv_path",
        default=None,
        help="생략하면 --output과 같은 디렉터리에 dataset.errors.csv로 생성한다",
    )
    _add_extractors_argument(batch)

    batch_local = subparsers.add_parser(
        "batch-local",
        help=(
            "npm-malware-package-pairs 로컬 클론에서 registry에서 이미 삭제된 "
            "악성 pair를 읽어 dataset.csv를 생성한다 (label은 항상 1)"
        ),
    )
    batch_local.add_argument(
        "--archive-root",
        required=True,
        type=Path,
        help="npm-malware-package-pairs를 로컬에 클론한 경로 (pairs/<campaign>/<pair_dir>/meta.json 구조)",
    )
    batch_local.add_argument("--output", required=True, type=Path, dest="output_csv_path")
    batch_local.add_argument(
        "--errors-output",
        type=Path,
        dest="errors_csv_path",
        default=None,
        help="생략하면 --output과 같은 디렉터리에 dataset.errors.csv로 생성한다",
    )
    batch_local.add_argument(
        "--limit",
        type=int,
        default=None,
        help="처리할 최대 pair 수. 전체 dataset을 생성하기 전 소수로 먼저 검증할 때 사용",
    )
    _add_extractors_argument(batch_local)

    batch_manifest = subparsers.add_parser(
        "batch-manifest",
        help=(
            "pair마다 old/new 출처(registry 또는 archive)를 지정한 manifest로 dataset.csv를 "
            "생성한다 (예: archive의 악성 버전 + registry의 baseline)"
        ),
    )
    batch_manifest.add_argument(
        "--manifest",
        required=True,
        type=Path,
        dest="manifest_path",
        help="package,old_version,new_version,label,old_source,new_source 컬럼을 가진 CSV. "
        "출처는 'registry' 또는 'archive:<archive-root 기준 raw 디렉터리>'",
    )
    batch_manifest.add_argument(
        "--archive-root",
        type=Path,
        default=None,
        help="manifest에 archive: 출처가 있을 때 필요한 npm-malware-package-pairs 로컬 클론 경로",
    )
    batch_manifest.add_argument("--output", required=True, type=Path, dest="output_csv_path")
    batch_manifest.add_argument(
        "--errors-output",
        type=Path,
        dest="errors_csv_path",
        default=None,
        help="생략하면 --output과 같은 디렉터리에 dataset.errors.csv로 생성한다",
    )
    _add_extractors_argument(batch_manifest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        extractors = resolve_extractors(args.extractors)
    except ValueError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - parser.error()가 SystemExit을 발생시킴

    if args.command == "single":
        try:
            row = build_row(args.package, args.old_version, args.new_version, args.label, extractors)
        except FeatureExtractorError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(row.to_flat_dict())
        return 0

    if args.command == "batch":
        errors_csv_path = args.errors_csv_path or args.output_csv_path.with_name("dataset.errors.csv")
        try:
            run_batch(args.pairs_file, args.output_csv_path, errors_csv_path, extractors)
        except _PATH_ERRORS as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID_INPUT
        return 0

    if args.command == "batch-local":
        errors_csv_path = args.errors_csv_path or args.output_csv_path.with_name("dataset.errors.csv")
        try:
            run_local_archive_batch(
                args.archive_root, args.output_csv_path, errors_csv_path, extractors, limit=args.limit
            )
        except _PATH_ERRORS as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID_INPUT
        return 0

    if args.command == "batch-manifest":
        errors_csv_path = args.errors_csv_path or args.output_csv_path.with_name("dataset.errors.csv")
        try:
            run_manifest_batch(
                args.manifest_path,
                args.output_csv_path,
                errors_csv_path,
                extractors,
                archive_root=args.archive_root,
            )
        except (*_PATH_ERRORS, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_INVALID_INPUT
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
