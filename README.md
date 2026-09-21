# feature-extractor

npm package의 (old_version, new_version) pair로부터 LightGBM 학습용 feature를 추출해 dataset을 생성하는 **개발/데이터셋 생성용** 도구입니다.

> 이 repo의 CLI는 최종 사용자용이 아닙니다. 학습된 모델을 사용하는 최종 CLI/서비스는 별도 repo `npm-update-guard`에서 구현됩니다.

## 관련 repository

- `npm-malware-package-pairs`: 분석 대상 package pair(`pairs.csv`) 원본 관리. 이 repo는 그 경로만 입력으로 받으며 내용을 소유하지 않습니다.
- `feature-extractor` (이 repo): feature 추출 및 dataset(`dataset.csv`) 생성.
- `npm-update-guard`: 학습된 모델을 사용하는 최종 사용자 CLI/서비스.

## 설치

```bash
pip install -e ".[dev]"
```

## 사용법

```bash
# 단일 pair 디버깅 (테스트/개발용)
feature-extractor single --package event-stream --old 3.3.5 --new 3.3.6 --label 1
feature-extractor single --package event-stream --old 3.3.5 --new 3.3.6 --label 1 --extractors package_json

# dataset 생성 (기본적으로 등록된 모든 extractor를 실행)
feature-extractor batch \
  --pairs-file ../npm-malware-package-pairs/data/pairs.csv \
  --output data/processed/dataset.csv
```

`--extractors`는 개발/디버깅 중 특정 extractor만 실행하고 싶을 때만 사용하는 옵션이며, 생략하면 `feature_extractor.extractors.EXTRACTOR_REGISTRY`에 등록된 모든 extractor가 실행됩니다.

`pairs.csv` 스키마: `package,old_version,new_version,label`

## 새 extractor 추가하기

1. `src/feature_extractor/extractors/`에 `BaseExtractor`를 상속한 클래스를 작성합니다(단일 `.py` 파일로 시작하고, 파일이 커지면 그때 같은 이름의 디렉터리로 승격).
2. `src/feature_extractor/extractors/__init__.py`의 `EXTRACTOR_REGISTRY`에 한 줄 등록합니다.
3. `required_data`에 필요한 데이터 종류(`"package_json"`, `"source"` 등)를 선언합니다. 이 값에 따라 `core/pipeline.py`가 loader 호출 여부(예: tarball 다운로드)를 자동으로 결정하므로, extractor나 CLI 사용자가 이를 직접 다룰 필요는 없습니다.
