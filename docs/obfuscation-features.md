# 난독화 feature 설계와 평가

`ObfuscationExtractor`(`src/feature_extractor/extractors/obfuscation.py`)의 feature 정의, 지표 선정 근거가 된 평가 결과, 남은 과제를 정리합니다.
구현과 registry 등록은 끝났습니다. 아래 "구현된 feature" 절이 현재 코드의 기준입니다.

## 범위

대상은 "이 업데이트에서 코드가 난독화된 형태로 바뀌었는가"입니다.
난독화 자체는 악성의 증거가 아니라 신호일 뿐이며, 실제 악성 행위(네트워크 전송, 자격증명 접근 등)를 판정하는 feature는 별도 extractor로 분리합니다.

소스 코드는 읽기만 합니다. 대상 패키지에 `npm install`이나 lifecycle script, 임의의 JS를 실행하지 않습니다.

## 출력 형식 (팀 합의)

추출기 담당 팀원과 맞춘 형식이며, `package_json` extractor 결과(`npm-malware-package-pairs/derived/package_json_features/`)와 같습니다.

1. 입력은 package name, old version, new version, label입니다.
2. package pair 하나당 결과 CSV 1행입니다.
3. 악성은 `label=1`, benign은 `label=0`입니다.
4. pair를 식별하는 `package`, `old_version`, `new_version` 컬럼 뒤에 난독화 feature 컬럼이 오고, 마지막이 `label`입니다.
5. 실패한 pair는 별도 `errors.csv`(`source_ref,package,old_version,new_version,reason`)에 기록합니다.

현재 파이프라인이 이 형식을 그대로 만들기 때문에 extractor는 feature dict만 반환하면 됩니다.

데이터별 실행 경로는 다릅니다.

- 악성(label=1): `batch-local --archive-root <npm-malware-package-pairs>`. 소스는 archive의 `malicious_raw`/`normal_raw`에서 읽습니다.
- benign(label=0): `batch --pairs-file <npm-malware-package-pairs>/derived/package_json_features/benign_package_json_features.csv`. archive에 benign 소스가 없으므로 registry에서 tarball을 받습니다. 이 CSV에는 `package,old_version,new_version,label` 컬럼이 있어 pairs 파일로 그대로 쓸 수 있습니다(나머지 컬럼은 무시됩니다).

결과 파일 배치는 아직 정하지 않았습니다. 기존 관례대로 extractor별로 CSV를 따로 두려면(`derived/obfuscation_features/`) `--extractors obfuscation`으로 실행합니다. 다만 extractor마다 실패하는 pair가 달라 CSV끼리 행 집합이 다를 수 있으니, 합칠 때는 `package,old_version,new_version`으로 join해야 합니다.

## 입력

`core/source_files.collect_source_files(snapshot)`이 `SourceFileSet`을 돌려줍니다.

- 대상 확장자는 `.js`, `.mjs`, `.cjs`이고 `node_modules/`, `.git/`은 제외합니다.
- 경로는 패키지 루트(`package.json`이 있는 디렉터리) 기준 POSIX 상대 경로이며, registry tarball과 local archive 어느 쪽에서 왔든 같은 의미를 갖습니다.
- 파일 수·크기 상한을 넘거나 디렉터리를 읽지 못하면 일부만 읽고 넘어가지 않고 `ExtractionError`를 냅니다.
- `SourceFileSet.by_relative_path()`로 old/new를 파일 단위로 대응시킬 수 있습니다.

## 평가 결과 (2026-09-22)

후보 지표 21개를 프로토타입으로 구현해 두 방식으로 평가했습니다. 평가 코드는 아직 저장소에 넣지 않았습니다.

### 평가 당시 extractor 상태

- 소스 수집 단계는 악성 729쌍(archive)과 benign 500쌍(registry tarball) 전부에서 실패 없이 동작했습니다. registry tarball 경로를 실제 registry로 돌린 것은 이때가 처음입니다.
- 평가 시점에는 지표 계산이 구현되지 않은 상태였고, 아래 수치는 후보 지표 21개를 따로 구현해 잰 것입니다. 이 결과로 고른 8개가 "구현된 feature" 절의 지표입니다.

### 1. 기법별 탐지 (합성 벤치마크, 파일 단위)

`normal_raw`의 읽기 쉬운 JS 파일 300개에 기법별 변환을 적용했습니다. 정상 쪽은 원본, 공백·주석 제거본, terser류 식별자 축약본, 실제 `.min.js` 44개, 실제 번들 200개입니다. 탐지율은 정상 전체의 오탐률이 1% 이하가 되는 임계값 기준입니다.

| 기법 | 잡는 지표 (단일 지표 탐지율) | 조합 모델, 학습에 없던 기법일 때 |
| --- | --- | ---: |
| 식별자 `_0x` 치환 | `hexIdentRatio` 99% | 99% |
| 문자열 배열 (+base64) | `hexIdentRatio` 100%, `hexNumberRatio` 99~100% | 100% |
| javascript-obfuscator 유사 조합 | `hexIdentRatio`, `hexNumberRatio`, `bracketAccessRatio` 100% | 100% |
| 문자열 16진 이스케이프 | `escapeDensity` 99% | 0% |
| packer (`eval(function(p,a,c,k,e,d)`) | `packerSignature`, `shortIdentRatio` 100% | 0% |
| 큰 정상 파일에 작은 난독화 코드 삽입 | `hexIdentRatio` 100% | 100% |
| `eval(Buffer.from(base64))` 전체 페이로드 | `whitespaceRatio` 100%만 | 100% |
| `new Function(String.fromCharCode(...))` | `whitespaceRatio` 100%만 | 100% |

- 줄 길이, 엔트로피, 문자열 길이, base64·hex 연속 길이는 어떤 기법도 오탐률 1%에서 잡지 못했습니다. 실제 `.min.js`와 번들이 같은 범위의 값을 가지기 때문입니다. 이 지표들은 난독화가 아니라 minify·번들 신호이며, 단독으로 쓰면 실제 `.min.js` 오탐률이 최대 20%입니다.
- `eval`/`Function` 호출 수와 디코딩 호출 수도 정상 번들에 흔해(4~7%) 단독으로는 쓸 수 없습니다.
- 조합 모델은 학습한 기법을 99~100% 잡습니다. 이때 정상 오탐률 1% 임계값에서 실제 `.min.js`의 4.5%, 번들의 2.5%가 오탐됐습니다.
- 학습에 없던 기법 중 다른 기법과 신호를 공유하지 않는 것(16진 이스케이프, packer)은 0%였습니다. 지도학습 모델은 본 적 있는 난독화와 닮은 것만 잡습니다.
- 평가하지 않은 기법: JSFuck·aaencode·jjencode, 제어 흐름 평탄화, dead code 삽입, self-defending. 변환은 직접 작성한 것이라 실제 도구 출력과 다를 수 있습니다.

### 2. 실제 악성 페이로드

| campaign | pair | 고유 페이로드 | 형태 | `hexIdentRatio` 발화율 |
| --- | ---: | ---: | --- | ---: |
| sha1-hulud-second-coming | 331 | 2 | javascript-obfuscator 출력 | 100% |
| mini-shai-hulud | 173 | 24 | javascript-obfuscator 출력 | 88% |
| shai-hulud-original | 164 | 8 | webpack 번들(minify), 난독화 아님 | 0% |
| canisterworm | 54 | 7 | 주석이 달린 평범한 코드 | 0% |
| sap-maintainer-compromise | 4 | 3 | javascript-obfuscator 출력 | 100% |
| individual-compromise | 2 | 2 | 번들 + 큰 base64 덩어리 | 50% |

benign 500쌍에서의 발화율은 0%(0/500)입니다. 발화율은 변경된 파일 기준이고, 임계값은 benign 오탐률 1% 기준입니다.

- 악성 729쌍은 가장 큰 변경 파일 기준으로 고유 페이로드 46개입니다. 그중 난독화된 것은 29개(3개 campaign, pair 기준 약 70%)이고 모두 javascript-obfuscator 계열입니다.
- `stringArraySignature`는 실제 데이터에서 한 번도 발화하지 않았습니다. 최신 javascript-obfuscator는 문자열 배열을 `var _0x…=[`로 선언하지 않고 함수 안에 넣습니다. 또 "문자열 30개 이상의 배열" 조건은 실제 `.min.js`의 39%, 번들의 21%에서 켜집니다. 시그니처 패턴은 도구 버전에 취약하므로 비율 지표를 기본으로 씁니다.
- 변경 파일 기준(`chg_`)이 새 버전 전체(`new_`)나 증가량(`delta_`)보다 모든 지표에서 AUC가 높았습니다.

### 3. 악성 판별 정확도 (LightGBM, 악성 728 + benign 500)

탐지율은 benign 오탐률 1% 임계값 기준입니다.

- **무작위 5-fold**에서는 모든 feature 조합이 AUC 0.99 이상이었고, package_json feature 7개만으로도 AUC 0.998이었습니다. 같은 페이로드가 학습과 평가에 반복돼 부풀려진 값이므로 성능 근거로 쓰지 않습니다.
- **campaign 하나를 통째로 빼고 학습**(처음 보는 공격)했을 때의 탐지율입니다.

| feature | sha1-hulud | mini-shai-hulud | shai-hulud-original | canisterworm | sap | individual | pair 가중 평균 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| package_json만 | 0.99 | 0.74 | 0.88 | 0.94 | 1.00 | 0.50 | 0.902 |
| 난독화(변경 파일)만 | 1.00 | 0.97 | 1.00 | 0.00 | 1.00 | 0.00 | 0.915 |
| package_json + 크기 + 난독화 | 1.00 | 0.97 | 1.00 | 0.00 | 1.00 | 1.00 | 0.919 |
| 위와 같음, 페이로드 중복 제거 | 1.00 | 0.97 | 0.99 | 0.93 | 1.00 | 1.00 | 0.986 |

- 난독화 feature의 실제 기여는 mini-shai-hulud에서 드러납니다(0.74 → 0.97).
- 중복을 제거하지 않으면 canisterworm 탐지율이 package_json만 쓸 때의 0.94에서 0.00으로 떨어집니다. 학습 데이터 대부분이 난독화된 거대 번들이라 모델이 "악성 = 난독화"라는 지름길을 배우기 때문입니다. campaign 균형 가중치로는 해결되지 않았고, 페이로드 중복 제거로 해결됐습니다.
- shai-hulud-original은 난독화가 아니라 줄 길이·크기 같은 번들 신호로 잡힙니다. benign 표본에 "번들이 새로 생기는 정상 업데이트"가 거의 없어서 가능한 결과이며, 일반화된다고 보기 어렵습니다.

한계:

- benign은 인기 패키지 500쌍입니다. `installScriptAdded`가 0%라 package_json feature가 실제보다 쉬워 보입니다.
- 악성 유효 표본은 46개이고, 난독화된 campaign은 모두 같은 도구 계열입니다. "처음 보는 campaign" 평가가 "처음 보는 난독화 도구"까지 검증하지는 못합니다.
- 임계값을 고른 benign 표본과 오탐률을 잰 표본이 같아 오탐률이 낙관적입니다. 0/500의 95% 신뢰 상한은 약 0.6%입니다.

### 4. 직접 구현과 라이브러리 비교 (실제 도구 출력, 2026-09-23)

1~3의 난독화 샘플은 직접 작성한 변환이었으므로, 실제 도구 출력으로 다시 쟀습니다.

- **난독화 샘플:** 읽기 쉬운 정상 파일 150개를 실제 도구로 변환한 1,295개입니다. javascript-obfuscator 5.8.0은 프리셋 4종과 `_0x` 대신 짧은 이름을 쓰는 회피 설정 2종, 유니코드 이스케이프 설정을 썼습니다. 그 밖에 js-confuser 2.1.3 프리셋 3종과 jsfuck 0.4.0입니다. js-confuser medium·high는 ES module 문법을 처리하지 못해 CommonJS 파일로만 구성됩니다.
- **정상 샘플:** 원본, terser 5.51.2 minify, normal_raw 무작위 1,000개, 실제 `.min.js`, 실제 번들입니다. 절반은 임계값 보정에, 나머지 772개는 오탐률 측정에 썼습니다.
- **비교 대상:**
  - 직접 구현: 정규식·문자 통계 지표. 규칙 방식과, 도구 계열 하나를 빼고 학습한 LightGBM 모델
  - `obfuscation-detector` 3.1.1: AST 구조 패턴으로 판별하는 Node 라이브러리
  - `jsbeautifier` 2.0.3 unpacker 탐지 함수
  - 직접 구현 지표와 라이브러리 라벨을 함께 넣은 조합 모델

| 판별 방식 | 도구 출력 탐지율 | 정상 오탐률 | 실제 난독화 페이로드 |
| --- | --- | ---: | --- |
| 직접 구현, 학습 없는 규칙 | js-confuser medium을 빼고 99~100% (medium 2%) | 1.0% | 전부 탐지(mini-shai-hulud `tool.js` 2개 제외) |
| 직접 구현, 처음 보는 도구 계열 | 92~100% | 1.0% | 규칙과 같음 |
| `obfuscation-detector`, 라벨 하나라도 | javascript-obfuscator 100%, js-confuser 0~5%, jsfuck 0% | **50.3%** | 잡음 라벨로 난독화 아닌 campaign까지 발화 |
| `jsbeautifier` | 0% | 0% | 0/44 |
| 조합 모델, 처음 보는 도구 계열 | 92~100% | 0.6% | 직접 구현과 같음 |

`obfuscation-detector`의 라벨별 결과:

- 오탐률 0%인 라벨(`augmented_proxied_array_function_replacements`, `obfuscator_io`, `sequenced_index_switch`)은 모두 javascript-obfuscator만 다룹니다. 이 라벨들은 실제 mini-shai-hulud 페이로드 23개 중 5개만 잡았고, 직접 구현은 21개를 잡았습니다. `obfuscator_io` 라벨은 실제 악성 44개 중 하나도 잡지 못했습니다.
- `cff_storage_object`는 정상 파일의 47.7%에서 발화합니다. `js_confuser_string_bank`는 js-confuser 2.x 출력을 하나도 잡지 못하고 정상 번들에서 발화합니다.
- 직접 구현이 놓친 실제 악성 페이로드를 정밀 라벨로 잡은 경우는 없었습니다.
- 공개 API는 파싱 실패 시 빈 결과를 돌려주어 "난독화 아님"과 구분되지 않습니다. 정상 파일의 3%(32개)가 여기에 해당했습니다.
- jsfuck 출력 8개에서는 8GB 힙 제한으로도 메모리 부족으로 종료됐습니다.
- 1MB 이상 파일의 처리 시간 중앙값은 2.1초로, 직접 구현(0.7초)의 약 3배였습니다.

조합 모델은 정상 772개 중 오탐을 8건에서 5건으로 줄였습니다. 대신 도구 출력 탐지가 6건 줄었고, 조합 모델만 잡은 샘플은 없었습니다.

**결론: 직접 구현을 채택하고 라이브러리는 의존성으로 넣지 않습니다.**

- 직접 구현이 더 넓게 잡습니다. js-confuser, jsfuck, 식별자 회피 설정까지 잡고, 실제 악성 페이로드도 더 많이 잡습니다.
- 조합했을 때 얻는 이득(오탐 3건 감소)이 비용보다 작습니다. 비용은 다음과 같습니다.
  - 추론 환경(`depbee` 포함)에 Node와 npm 의존성 164개가 추가됩니다.
  - 파싱 실패가 조용히 누락됩니다.
  - 큰 파일에서 메모리 부족으로 종료됩니다.
- 도구 이름 같은 설명 근거가 필요해지면, 오탐률 0%인 라벨만 버전을 고정해 별도 근거(evidence)로 붙이는 방안을 다시 검토합니다.

직접 구현의 남은 오탐은 두 종류입니다.

- TypeScript enum을 컴파일한 작은 파일(`E[E["A"] = 0] = "A"` 형태)에서 `bracketAccessRatio`가 오탐합니다. 5건입니다.
- 실제 minify 파일에서 `shortIdentRatio`·`meanIdentLength`가 오탐합니다. 3건입니다.

### 5. 어려운 benign과 번들 신호 (2026-09-23)

무작위 benign에는 설치 스크립트를 추가한 정상 업데이트가 없고, 번들이 새로 생기는 경우도 드뭅니다. 그래서 registry에서 이런 "어려운" 정상 업데이트 299쌍을 따로 골랐습니다. 샘플링·OSV 대조·그룹 파일 스크립트와 결과 CSV는 `npm-malware-package-pairs/derived/pairs/`에 있습니다.

- 설치 스크립트 추가 150쌍: 새 버전에 이전에 없던 `preinstall`·`install`·`postinstall`이 생긴 연속 버전입니다.
- 크기 급증 149쌍: `unpackedSize`가 3배 이상, 1MB 이상으로 늘어난 연속 버전입니다.

고르는 과정에서 1쌍(`executable-stories-playwright` 8.4.2 → 3.1.1)이 실제 악성으로 확인돼 뺐습니다. OSV에 `MAL-2026-5256`으로 등록돼 있고, Windows Defender가 `Trojan:NPM/MiniShaiHrd.ZA!MTB`로 탐지했습니다. benign 2,300쌍의 old/new 버전 전체를 OSV와 대조했을 때 악성 등록 버전은 이 1건뿐이었습니다. registry에서 benign을 뽑을 때는 OSV 대조를 기본 단계로 두는 것이 좋습니다.

검증 방식은 campaign 하나를 통째로 빼고 학습하고, 페이로드 중복을 제거하는 것입니다. 임계값은 무작위 benign 오탐률 1%로 정하고, 어려운 benign 오탐률은 종류별로 따로 쟀습니다. 크기 feature(SIZE)는 변경 파일 수와 바이트 수, 번들 feature(BUNDLE)는 줄 길이·엔트로피·긴 문자열·base64 길이입니다.

| 학습에 쓴 benign | feature | 가중 탐지율 | canisterworm | shai-hulud-original | 설치 스크립트 추가 오탐 | 크기 급증 오탐 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 무작위만 | package_json + 난독화 | 0.977 | 0.94 | 0.95 | **98.9%** | 12.6% |
| 무작위 + 어려운 | package_json + 난독화 | 0.872 | 0.00 | 0.84 | 10.8% | 7.6% |
| 무작위 + 어려운 | + SIZE | 0.912 | 0.04 | 1.00 | 7.6% | 5.9% |
| 무작위 + 어려운 | + BUNDLE | 0.905 | 0.00 | 0.95 | 7.6% | 9.4% |
| 무작위 + 어려운 | + BUNDLE + SIZE | 0.916 | 0.00 | 1.00 | 6.0% | 7.0% |

- **어려운 benign은 학습에 꼭 넣어야 합니다.** 무작위 benign만으로 학습하면 설치 스크립트를 추가한 정상 업데이트의 98.9%를 악성으로 판정합니다. 모델이 "설치 스크립트 추가 = 악성"을 배우기 때문입니다.
- **넣으면 canisterworm을 못 잡습니다(0.94 → 0.00).** canisterworm은 난독화 없는 평범한 코드에 설치 스크립트를 추가합니다. 설치 스크립트 추가가 정상 업데이트에도 있는 일이 되면, 지금 feature로는 둘을 구분할 근거가 없습니다. 팀 설계의 행동 feature(네트워크, 프로세스 실행, 환경변수 접근과 그 설치 문맥)가 필요합니다.
- **번들 신호보다 크기·변경량 feature가 낫습니다.** 크기 feature를 더하면 shai-hulud-original 탐지가 0.84에서 1.00으로 오르고 어려운 benign 오탐도 줄었습니다. 줄 길이 같은 번들 지표는 크기 feature 위에 얹어도 이득이 거의 없었습니다.
- **결론:** 줄 길이 번들 지표는 넣지 않습니다. 크기·변경량 feature는 난독화가 아니라 "무엇이 얼마나 바뀌었나"에 대한 것이므로, 난독화 extractor가 아니라 팀 설계 A-2(변경점 중심) 성격의 별도 extractor로 두는 것을 제안합니다.

## 구현된 feature

지표 7개를 파일별로 계산하고, 팀 설계(방안 1+2)에 맞춰 세 가지 값으로 냅니다. 컬럼 이름은 `obf` + 지표 이름 + 접미어입니다(예: `obfHexIdentRatioChangedCode`).

| 지표 | 의미 | 난독화 쪽 |
| --- | --- | --- |
| `HexIdentRatio` | `_0x…` 형태 식별자 비율 | 클수록 |
| `HexNumberRatio` | 숫자 리터럴 중 `0x…` 16진 표기 비율 | 클수록 |
| `BracketAccessRatio` | 멤버 접근 중 `obj['x']`, `obj[_0x1(0x2)]` 형태 비율. TypeScript enum 컴파일 코드는 제외 | 클수록 |
| `EscapeDensity` | `\xNN`, `\uNNNN` 이스케이프가 차지하는 문자 비율 | 클수록 |
| `ShortIdentRatio` | 길이 2 이하 식별자 비율 | 클수록 |
| `MeanIdentLength` | 식별자 평균 길이 | 작을수록 |
| `WhitespaceRatio` | 공백 문자 비율 | 작을수록 |

| 접미어 | 계산 대상 | 팀 설계상 위치 |
| --- | --- | --- |
| `New` | 새 버전의 모든 JS 파일 | A-1 new |
| `Change` | `New` - 이전 버전 전체 값 | A-1 change |
| `ChangedCode` | 이번 업데이트에서 추가되거나 내용이 바뀐 JS 파일 | A-2 |

그 밖에 `obfChangedFileCount`(추가·수정된 JS 파일 수)를 냅니다.

- **집계:** 파일 여러 개는 난독화 쪽 극값으로 모읍니다. "클수록" 지표는 최대값, "작을수록" 지표는 1KB 이상 파일의 최소값입니다. 파일 하나만 난독화된 경우에도 신호가 희석되지 않게 하기 위해서입니다.
- **결측:** 계산할 파일이 없으면 0으로 채우지 않고 빈 값(None)으로 둡니다. CSV에서는 빈 칸이고 LightGBM에서는 결측으로 처리됩니다. 변경된 JS 파일이 없으면 `...ChangedCode`가 모두 비고, JS 파일이 하나도 없는 패키지는 `obfChangedFileCount`를 뺀 전부가 빕니다. 이런 pair도 오류가 아니라 정상 행으로 기록합니다.
- **파일 단위 결측:** "작을수록" 지표는 파일에서 계산할 대상이 없으면 그 파일의 값을 None으로 두고 집계에서 뺍니다. `MeanIdentLength`는 식별자가 없는 파일(숫자 배열만 있는 데이터 파일, 주석뿐인 파일), `WhitespaceRatio`는 빈 파일이 해당합니다. 0으로 두면 최소값 집계에서 그 파일 하나가 패키지 값을 0으로 만들어 가짜 난독화 신호가 됩니다. 1KB 이상 파일 중 값이 있는 파일이 없으면 값이 있는 작은 파일을 보고, 값이 있는 파일이 하나도 없으면 패키지 값도 None입니다. "클수록" 지표는 그대로 0으로 둡니다. 최대값 집계에서 0은 다른 파일의 값을 가리지 않고, 이전 버전에 숫자가 없던 패키지에 16진 숫자가 생긴 경우처럼 None으로 두면 `...Change` 신호가 사라지기 때문입니다.
- **대상 파일:** `core/source_files.collect_source_files()` 기준입니다(`.js`/`.mjs`/`.cjs`, `node_modules/` 제외).
- **구현 방식:** Python 정규식·문자 통계로 계산하며, JS 파서나 판별 라이브러리를 쓰지 않습니다(4절).
- **평가 대비 변경:** TypeScript enum 컴파일 코드(`})(E || (E = {}))`로 끝나는 형태)의 멤버 정의를 대괄호 접근에서 뺐습니다. 평가 코퍼스에서 정상 오탐이 772개 중 8건에서 3건으로 줄었고, 도구별 탐지율은 그대로였습니다. 나머지 7개 지표는 평가 때 프로토타입과 같은 값을 내되, `MeanIdentLength`·`WhitespaceRatio`는 위 파일 단위 결측 처리가 추가됐습니다.

제외한 후보와 이유:

- `stringArraySignature`: 최신 javascript-obfuscator 출력에서 발화하지 않고, 긴 문자열 배열 조건이 정상 minify 코드에서 켜집니다.
- `PackerSignature`(`eval(function(p,a,c,k,e,d)` packer 흔적, 0/1): 처음에는 지표 8개 중 하나로 넣었다가 뺐습니다(2026-09-29). 합성 벤치마크(1절)에서는 packer를 100% 잡았지만, 실제 dataset(악성 849, 무작위 benign 1,999, 어려운 benign 299쌍)의 New·Change·ChangedCode 값이 전부 0이었고, 악성 archive의 `malicious_raw`·`normal_raw` JS 60,421개를 extractor 정규식과 느슨한 `function(p,a,c,k,e,` 패턴으로 모두 찾아도 0건이었습니다. 값이 상수라 학습에 쓸 정보가 없고, 결측 여부도 다른 지표와 같아 따로 담는 정보가 없었습니다. archive의 `eval(function(` 47건은 packer가 아니라 문자코드 배열을 푸는 ROT-n 디코더(`function(s,n)`)였습니다. 1절에서 packer는 `shortIdentRatio`로도 100% 잡혔습니다. packer 표본이 데이터에 들어오면 이 커밋 이전의 `_PACKER` 정규식과 `_packer_signature`를 `METRICS`에 되돌리고 전체를 다시 추출하면 됩니다.
- 줄 길이, 엔트로피, 문자열 길이, base64/hex 연속 길이: 난독화가 아니라 minify·번들 신호입니다.
- `eval`/`Function`·디코딩 호출 수: 정상 번들에 흔해 단독 신호가 되지 못합니다.

## 생성한 dataset

팀이 쓰는 결과는 `npm-malware-package-pairs/derived/obfuscation_features/`에 있습니다. `package_json_features/`와 같은 형식으로 난독화 feature만 담았고, 파일 설명은 그 디렉터리의 README에 있습니다.
package.json feature까지 함께 담은 학습용 합본은 `derived/combined_features/`에 있습니다. 이전에 만든 로컬 합본은 `data/processed/`(커밋 대상 아님)에 있고, 각 파일을 만든 커밋·입력·행 수는 `data/processed/MANIFEST.json`에 기록했습니다.

pair의 old는 같은 release line의 이전 stable 버전입니다(`derived/pairs/baseline_rule.py`, 규칙과 결과는 `derived/README.md`). new가 prerelease인 pair와 baseline이 없는 악성은 주 학습셋에서 빼 `combined_features/holdout/`에 둡니다. 2026-09-29에 `batch-manifest`로 Linux에서 다시 추출했고, 2026-09-30에 4차 수집 111쌍을 같은 규칙과 파이프라인으로 덧붙였습니다.

- `malicious_combined_features.csv`: 악성 주 학습셋 947행(baseline 없는 14쌍은 holdout, errors 77행은 archive 상태 문제).
- `benign_combined_features.csv`: 무작위 benign 2,000행(부족분은 같은 규칙으로 재샘플링).
- `hard_benign_combined_features.csv`: 어려운 benign 299쌍(`install_script_added` 150, `bundle_growth` 149, 5절).
- `derived/pairs/malicious_pair_groups.csv`: 악성 pair별 campaign과 페이로드 해시(주 학습셋 947 + holdout 14 = 961행). 학습할 때 중복 제거와 campaign 단위 분할에 씁니다. 고유 페이로드는 (campaign, 해시) 기준으로 가장 큰 변경 파일 145개, 변경 파일 전체 148개입니다(주 학습셋만 143개, 146개). 추가·수정된 JS가 없는 129쌍은 해시가 빈 값이고, 위 수에는 campaign마다 빈 값 하나로 들어 있습니다. `splitGroup`은 Train/Test에서 한쪽에만 들어가야 하는 묶음으로, campaign 22개가 그대로 22개 group이 됩니다. 같은 악성 의존성 `easy-day-js`를 추가한 4차 수집의 `@mastra/*` 104쌍은 `mastra-easy-day-js_2026-06`에 합쳐 이 group이 119쌍입니다.
- `derived/pairs/excluded_benign_pairs.csv`, `derived/pairs/benign_osv_screening.csv`: benign에서 뺀 pair와 OSV 대조 결과.

## 남은 과제

1. **행동 feature.** canisterworm처럼 난독화 없이 설치 스크립트만 추가하는 공격은 package.json·난독화 feature로 정상과 구분되지 않습니다(5절). 네트워크, 프로세스 실행, 환경변수 접근과 그 설치 문맥 feature가 필요합니다.
2. **변경량 extractor.** 변경 파일 수·바이트 같은 크기 feature를 별도 extractor로 둘지 팀에서 정합니다(5절).
3. **학습.** 어려운 benign을 학습 데이터에 넣고, `malicious_pair_groups.csv`로 페이로드 중복을 제거하며, campaign 단위로 나눠 평가합니다. 무작위 분할 수치는 보고하지 않습니다.
4. **남은 오탐.** 실제 minify 파일에서 `ShortIdentRatio`·`MeanIdentLength`가 오탐합니다(3건). 정상 minify 표본을 학습 데이터에 충분히 넣어야 합니다.
5. **benign 수집 시 OSV 대조.** registry에서 benign을 뽑을 때 악성 등록 버전을 걸러내는 단계를 기본으로 둡니다.
