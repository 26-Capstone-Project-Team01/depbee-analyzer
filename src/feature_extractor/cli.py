from __future__ import annotations

import argparse
import sys
from pathlib import Path

from feature_extractor.core.errors import FeatureExtractorError
from feature_extractor.core.pipeline import build_row, resolve_extractors, run_batch


def _split_extractor_names(value: str) -> list[str]:
    return [name.strip() for name in value.split(",") if name.strip()]


def _add_extractors_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--extractors",
        type=_split_extractor_names,
        default=None,
        metavar="NAME[,NAME...]",
        help=(
            "쉼표로 구분된 extractor 이름 목록. 생략하면 등록된 모든 extractor를 실행한다 "
            "(개발/디버깅 전용 옵션이며, dataset 생성 시에는 생략해 전체 실행하는 것이 기본값이다)"
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feature-extractor",
        description=(
            "npm package.json / obfuscation feature 추출 도구. "
            "개발·dataset 생성용이며 최종 사용자 CLI는 npm-update-guard repo에 있다."
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
        run_batch(args.pairs_file, args.output_csv_path, errors_csv_path, extractors)
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
