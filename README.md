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

`obfuscation` extractor는 소스 코드가 필요하므로, 기본 실행 시 `batch`는 pair마다 두 버전의 tarball을 registry에서 내려받습니다. 받은 tarball은 pair 처리가 끝나면 지웁니다. package.json feature만 필요하면 `--extractors package_json`으로 다운로드를 건너뛸 수 있습니다. `batch-local`은 archive에 있는 소스를 읽으므로 tarball을 받지 않습니다.

`pairs.csv` 스키마: `package,old_version,new_version,label`

## 현재 상태

| extractor | 상태 |
| --- | --- |
| `package_json` | 구현 완료, registry 등록됨 |
| `obfuscation` | 구현 완료, registry 등록됨. 난독화 지표 8개를 새 버전 전체(`...New`), 이전 대비 변화(`...Change`), 변경된 코드(`...ChangedCode`) 세 가지로 냅니다(`obf` 접두어, 25개 컬럼). 지표 선정 근거와 평가는 [docs/obfuscation-features.md](docs/obfuscation-features.md) 참고 |

## 새 extractor 추가하기

1. `src/feature_extractor/extractors/`에 `BaseExtractor`를 상속한 클래스를 작성합니다(단일 `.py` 파일로 시작하고, 파일이 커지면 그때 같은 이름의 디렉터리로 승격).
2. `src/feature_extractor/extractors/__init__.py`의 `EXTRACTOR_REGISTRY`에 한 줄 등록합니다.
3. `required_data`에 필요한 데이터 종류(`"package_json"`, `"source"` 등)를 선언합니다. 이 값에 따라 `core/pipeline.py`가 loader 호출 여부(예: tarball 다운로드)를 자동으로 결정하므로, extractor나 CLI 사용자가 이를 직접 다룰 필요는 없습니다.

### 소스 코드를 보는 extractor

`required_data`에 `"source"`를 선언하면 `PackageVersionSnapshot.source_dir`에 해당 버전의 소스 트리가 채워집니다. 이 값은 어느 snapshot source를 쓰든 `package.json`이 들어있는 패키지 루트를 가리킵니다.

파일을 직접 순회하는 대신 `core/source_files.collect_source_files(snapshot)`을 사용하세요. 대상 확장자, 제외 디렉터리, 크기·개수 상한을 한 곳에서 정의해 extractor마다 feature의 모집단이 달라지는 것을 막습니다. 이 도구는 대상 패키지의 코드를 읽기만 하며 실행하지 않습니다.
