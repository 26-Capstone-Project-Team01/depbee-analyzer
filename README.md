# depbee-analyzer

npm package의 (old_version, new_version) pair로부터 LightGBM 학습용 feature를 추출해 dataset을 생성하는 **개발/데이터셋 생성용** 도구입니다.

> 이 repo의 CLI는 최종 사용자용이 아닙니다. 학습된 모델을 사용하는 최종 CLI/서비스는 별도 repo `depbee`에서 구현됩니다.

배포명과 CLI는 `depbee-analyzer`, Python import는 `depbee_analyzer`입니다.

## 관련 repository

- `npm-malware-package-pairs`: 분석 대상 package pair(`pairs.csv`) 원본 관리. 이 repo는 그 경로만 입력으로 받으며 내용을 소유하지 않습니다.
- `depbee-analyzer` (이 repo): feature 추출 및 dataset(`dataset.csv`) 생성.
- `depbee`: 학습된 모델을 사용하는 최종 사용자 CLI/서비스.

## 설치

새 checkout에서 가상 환경을 만들고 활성화한 뒤 저장소 루트에서 설치합니다.

```bash
python -m pip install -e ".[dev]"
depbee-analyzer --help
python -m depbee_analyzer.cli --help
```

기존 편집 설치 환경을 그대로 옮길 때는 그 환경에서 `python -m pip uninstall feature-extractor`를 실행하고 이름이 변경된 커밋으로 checkout합니다. 이때 `src/feature_extractor/`에 캐시만 남았거나 `src/feature_extractor.egg-info/`에 이전 설치 메타데이터가 남았다면 사용자 파일이 없는지 확인한 뒤 해당 생성물만 정리하고 위 설치 명령을 실행하세요. 호출하는 코드의 import도 `depbee_analyzer`로 바꿉니다.

기존 실험을 재현할 때는 기록된 전체 커밋 SHA를 별도 checkout과 가상 환경에 고정하세요. 예를 들어 `c24761d`에서는 배포명·콘솔이 `feature-extractor`이고 모듈은 `feature_extractor.cli`입니다. `a83cc4b`부터 새 이름을 사용합니다. 두 커밋의 배포 버전은 모두 `0.1.0`이므로 실험 기록에는 버전과 SHA를 함께 남깁니다.

## 사용법

```bash
# 단일 pair 디버깅 (테스트/개발용)
depbee-analyzer single --package event-stream --old 3.3.5 --new 3.3.6 --label 1
depbee-analyzer single --package event-stream --old 3.3.5 --new 3.3.6 --label 1 --extractors package_json

# dataset 생성 (기본적으로 등록된 모든 extractor를 실행)
depbee-analyzer batch \
  --pairs-file ../npm-malware-package-pairs/data/pairs.csv \
  --output data/processed/dataset.csv
```

`--extractors`를 생략하면 `depbee_analyzer.extractors.EXTRACTOR_REGISTRY`에 등록된 모든 extractor가 실행되고, 결과가 한 CSV에 함께 들어갑니다. 쉼표로 이름을 주면 그 extractor의 feature만 담긴 CSV가 나옵니다.

```bash
# 난독화 feature만 (extractor별로 dataset을 따로 둘 때)
depbee-analyzer batch-local --archive-root ../npm-malware-package-pairs --output data/processed/malicious_obf.csv --extractors obfuscation

# package.json feature만 (tarball 다운로드 없음)
depbee-analyzer batch --pairs-file ../npm-malware-package-pairs/data/pairs.csv --output data/processed/dataset.csv --extractors package_json
```

pair마다 old/new를 어디서 읽을지 다르게 지정해야 할 때는 `batch-manifest`를 씁니다. 예를 들어 악성 버전은 registry에서 삭제돼 archive에서 읽고, baseline은 archive에 없는 같은 release line의 버전이라 registry에서 받는 경우입니다.

```bash
depbee-analyzer batch-manifest \
  --manifest ../npm-malware-package-pairs/derived/pairs/baselines.csv \
  --archive-root ../npm-malware-package-pairs \
  --output data/processed/dataset.csv
```

manifest 컬럼은 `package,old_version,new_version,label,old_source,new_source`이고(다른 컬럼은 무시), 출처는 `registry` 또는 `archive:<archive-root 기준 raw 디렉터리>`입니다(예: `archive:axios_2026-03/axios/malicious_raw`). archive 밖을 가리키는 경로나 알 수 없는 출처가 있으면 결과 파일을 건드리기 전에 종료 코드 2로 멈춥니다.

extractor별 CSV를 합칠 때는 `package,old_version,new_version`으로 join합니다. extractor마다 실패하는 pair가 다를 수 있어 CSV끼리 행 집합이 같다는 보장은 없습니다.

`obfuscation` extractor는 소스 코드가 필요하므로, 기본 실행 시 `batch`는 pair마다 두 버전의 tarball을 registry에서 내려받습니다. 받은 tarball은 pair 처리가 끝나면 지웁니다. `batch-local`은 archive에 있는 소스를 읽으므로 tarball을 받지 않습니다.

`pairs.csv` 스키마: `package,old_version,new_version,label`

## 현재 상태

| extractor | 상태 |
| --- | --- |
| `package_json` | 구현 완료, registry 등록됨 |
| `obfuscation` | 구현 완료, registry 등록됨. 난독화 지표 7개를 새 버전 전체(`...New`), 이전 대비 변화(`...Change`), 변경된 코드(`...ChangedCode`) 세 가지로 냅니다(`obf` 접두어, 22개 컬럼). 지표 선정 근거와 평가는 [docs/obfuscation-features.md](docs/obfuscation-features.md) 참고 |

## 새 extractor 추가하기

1. `src/depbee_analyzer/extractors/`에 `BaseExtractor`를 상속한 클래스를 작성합니다(단일 `.py` 파일로 시작하고, 파일이 커지면 그때 같은 이름의 디렉터리로 승격).
2. `src/depbee_analyzer/extractors/__init__.py`의 `EXTRACTOR_REGISTRY`에 한 줄 등록합니다.
3. `required_data`에 필요한 데이터 종류(`"package_json"`, `"source"` 등)를 선언합니다. 이 값에 따라 `core/pipeline.py`가 loader 호출 여부(예: tarball 다운로드)를 자동으로 결정하므로, extractor나 CLI 사용자가 이를 직접 다룰 필요는 없습니다.

### 소스 코드를 보는 extractor

`required_data`에 `"source"`를 선언하면 `PackageVersionSnapshot.source_dir`에 해당 버전의 소스 트리가 채워집니다. 이 값은 어느 snapshot source를 쓰든 `package.json`이 들어있는 패키지 루트를 가리킵니다.

파일을 직접 순회하는 대신 `core/source_files.collect_source_files(snapshot)`을 사용하세요. 대상 확장자, 제외 디렉터리, 크기·개수 상한을 한 곳에서 정의해 extractor마다 feature의 모집단이 달라지는 것을 막습니다. 이 도구는 대상 패키지의 코드를 읽기만 하며 실행하지 않습니다.
