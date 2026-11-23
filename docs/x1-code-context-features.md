# X1 코드 문맥 feature (`code_context`, 실험용)

9차 회의(11/20)의 X1: 설치 훅 공격(A 유형)과 변경 JS의 실행·통신 호출(C 유형)을 정적으로 뽑는다.
B 유형(새 의존성의 당시 버전 분석)은 별도 실험으로 남긴다.

- 코드: `src/depbee_analyzer/extractors/code_context.py`
- 정적 분석만 한다. 패키지 코드·lifecycle script·셸 명령을 실행하지 않고 npm install을 하지 않는다.
- 규칙 스캐너(`rules/diff_scan.py`)를 import하지 않으며 그 hit/no_hit을 feature로 쓰지 않는다.
- **기본 실행에 포함되지 않는다.** `OPTIONAL_EXTRACTOR_REGISTRY`에만 있고 `--extractors ...,code_context`로 켠다.
  depbee는 `resolve_extractors(None)`(기본 목록)을 쓰므로 고정 커밋을 올려도 `depbee-features-v1` 출력은 그대로다.

## feature

| 이름 | 타입 | 계산 | 결측(None) |
|---|---|---|---|
| `installHookNewProgramCount` | int ≥ 0 | new의 preinstall/install/postinstall 명령에 나오는 실행 프로그램 집합 − old의 집합의 크기 | 훅 명령을 셸 토큰으로 나누지 못함(따옴표 불일치), `scripts`가 객체가 아님, 훅 값이 문자열이 아님 |
| `installHookArgsChanged` | bool | 양쪽에 있는 같은 훅에서 명령 토큰은 다르고 실행 프로그램 구성(중복 포함)은 같음 | 위와 같음 |
| `installHookRefFileChanged` | bool | new 훅이 직접 실행하는 **패키지 내부** 파일(`node x.js`, `sh x.sh`, `./x.sh`, node는 `x`→`x.js`/`x/index.js`)이 old에 없거나 내용이 다름. 외부 실행 대상은 이 값에 넣지 않는다 | 바뀐 내부 파일이 확인되지 않았고, 내부 실행 대상 중 하나라도 확인 불가(패키지에 없음, symlink, 크기 상한 초과, source 없음). 훅 해석 실패 |
| `installHookNewExternalExecCount` | int ≥ 0 | new 훅의 **외부 실행 대상** 중 old 훅에 없던 것의 수(아래 정의) | 훅 해석 실패, `scripts` 형식 오류 |

**실행 대상**은 명령 위치의 경로(`./x`, `/x`, `~/x`, `$VAR/x`, 스크립트 확장자)와 인터프리터(node·sh·bash·python 등)의
첫 파일 인자만이다. `cp /tmp/a b`, `node build.js /tmp/out`의 `/tmp/...`처럼 인자로만 쓰인 경로는 실행 대상이 아니다.

**외부 실행 대상**(비교 키):
- `path:` 절대 경로, `~`·`$VAR`로 시작하는 경로, `..`로 패키지 밖을 가리키는 경로
- `download:` 같은 훅에서 `curl -o/--output`, `wget -O/--output-document`, `>`·`>>` 리디렉션으로 내려받은 파일(상대 경로 포함)
- `pipe:` 다운로더 출력을 인터프리터로 파이프(`curl ... | sh`)

old에도 같은 키가 있으면 세지 않는다(같은 외부 경로를 계속 실행하는 정상 설치기는 0, URL만 바뀐 경우는 `installHookArgsChanged`).
외부 실행 자체를 악성 판정으로 쓰지 않는다. 내용을 읽지 않으므로 source가 없어도 계산된다.

개선 전에는 외부 경로 실행이 `installHookRefFileChanged`를 None으로 만들어, "외부 경로를 실행한다"는 정보와
"파일을 분석할 수 없다"는 상황이 같은 결측으로 섞였다.
| `addedProcExecCallCount` | int ≥ 0 | **새로 생기거나 바뀐 호출 지점 수.** 추가·변경된 JS 파일마다 new의 호출 서명 multiset에서 old 같은 경로의 multiset을 뺀 개수의 합. 대상 API: `child_process`의 exec/execSync/execFile/execFileSync/spawn/spawnSync/fork | 소스 수집 실패(source 없음, 파일 수·크기 상한, 디렉터리 읽기 오류) |
| `addedNetworkCallCount` | int ≥ 0 | 같은 방식. 대상 API: http/https(request·get), http2.connect, net(connect·createConnection·Socket), tls.connect, dgram.createSocket, dns 조회, HTTP 라이브러리(axios, node-fetch, got, undici, ws 등) 호출, 전역 `fetch(`, `new WebSocket/XMLHttpRequest/EventSource(`, `navigator.sendBeacon(` | 위와 같음 |

**호출 서명** = (API 이름, 인자에 직접 적힌 문자열 리터럴들, 숫자 리터럴들). API 이름은 별칭이 아니라 모듈과 export 이름으로
정규화한다(`cp.exec`와 `require('child_process').exec`는 같은 `child_process.exec`). 그래서

| 변경 | 값 |
|---|---|
| `fetch("a")` → `fetch("b")` (호출 수 같음) | net 1 |
| `exec("기존 명령")` → `exec("새 명령")` (호출 수 같음) | proc 1 |
| 같은 파일에서 호출 하나 삭제 + 다른 호출 하나 추가 | 1 |
| `n.connect(80, h)` → `n.connect(4444, h)` | net 1 |
| 호출 순서만 바뀜, minified 번들의 변수 이름만 바뀜 | 0 |
| 인자 안의 자기 버전 문자열만 바뀜(`'--version=0.19.11'` → `'--version=0.19.12'`) | 0 |
| 호출 삭제만 | 0 |
| `exec(cmd)` → `exec(otherCmd)` (변수로만 전달된 대상 변경) | **0 (한계)** |

훅이 없거나 바뀐 JS 파일이 없으면 0/False이며 결측이 아니다.
A 유형은 source가 없어도 계산된다(`installHookRefFileChanged`는 내부 실행 대상이 있으면 None).

### 처음 제안에서 바꾼 점과 이유

- `installHookArgsChanged`: "실행 프로그램 구성은 같고 명령만 바뀜"으로 좁혔다. 프로그램이 바뀐 경우는
  `installHookNewProgramCount`가 맡아 두 feature가 겹치지 않는다. 기존 `installScriptAdded`는 훅 이름이 새로 생긴 경우만 보므로
  기존 훅의 명령 변경은 29개 feature에 없다.
- C 유형은 "추가된 줄"이 아니라 **파일 단위 호출 서명 차이**로 센다. minified 번들은 한 줄이 파일 전체라서 한 글자만 바뀌어도
  기존 호출이 모두 추가된 줄로 잡힌다. 처음 구현한 "호출 수 차이"는 호출 수가 같은 대상 변경(위 표 1~3행)을 놓쳐서 서명 비교로 바꿨다.
- 서명에 변수 이름을 넣지 않는다. minified 번들은 빌드마다 변수 이름이 바뀌어 같은 호출이 바뀐 호출로 잡히기 때문이다.
  대신 변수·식으로만 전달된 대상의 변경은 구분하지 못한다.
- 문자열 리터럴 안의 **비교 중인 old·new 버전 문자열만** 같은 토큰으로 바꿔 비교한다. 실제 정상 패키지 점검에서
  esbuild 0.19.11→0.19.12가 실행 인자의 자기 버전 문자열 때문에 proc 2로 잡혔기 때문이다. 다른 버전처럼 보이는 문자열은 그대로 비교한다.
- `.exec(`·`.spawn(` 같은 이름만으로 세지 않고 `require('child_process')`/`import ... from 'child_process'`로 묶인 이름의 호출만 센다
  (`RegExp.prototype.exec` 오탐 방지).
- 주석, 문자열, 정규식 리터럴 안은 세지 않는다(`lex_js`). 템플릿 리터럴의 `${...}` 안 식은 코드로 본다.

### 정적 분석 한계

- 셸: `$(...)` 명령 치환, 변수 확장, `node -e`의 인라인 코드는 해석하지 않는다. `sh/bash -c "..."`는 한 단계 펼친다.
  `2>&1`의 `2`처럼 일부 리디렉션 숫자가 인자로 남는다(프로그램 판정에는 영향 없음).
- JS: 완전한 파서가 아니다. 동적 require(`require(name)`), `obj[method]()`, 재할당된 alias, `(cond ? https : http).request`
  같은 간접 호출, 동적 `import()`는 세지 않는다. 지역 함수 이름이 `fetch`이면 전역 fetch로 센다. 통신 상대(localhost 포함)는 구분하지 않는다.
- 같은 호출을 다른 파일로 옮기면 새 파일 쪽에서 추가로 센다.
- 인자 리터럴: 문자열·숫자만 본다. 치환이 있는 템플릿 리터럴(`` `https://${host}/x` ``)의 고정 텍스트, 객체 리터럴의 키 이름,
  인자 범위 4,096자 이후는 서명에 들어가지 않는다. 문자열을 이어 붙인 값(`"ht" + "tp://..."`)은 조각 문자열 순서로 비교한다.
- `.js/.mjs/.cjs`만 본다(`core/source_files.py`와 같은 범위). `node_modules/`는 제외된다.

## 학습 연결

### 병합

`batch-manifest`로 extractor별 CSV를 만든 뒤 `package, old_version, new_version`으로 join한다.

```bash
depbee-analyzer batch-manifest --manifest ../npm-malware-package-pairs/derived/pairs/baselines.csv \
  --archive-root ../npm-malware-package-pairs --output data/processed/d06_x1.csv --extractors code_context
```

- 기존 29개 CSV(D06 `derived/splits/train.csv`)와 1:1 inner join이 아니라 **left join** 후 X1 행이 없는 쌍(추출 오류)을 따로 센다.
  X1 행이 없는 쌍을 0으로 채우지 않는다.
- CSV의 빈 칸은 None(결측)이다. bool은 `True/False`로 쓰이므로 학습 시 1.0/0.0, 빈 칸은 NaN으로 읽는다.

### `full29 + X1` 학습에 필요한 변경

- PR #13 스냅샷(`load_data`)은 Train CSV가 정확히 29개 feature이고 해시가 고정이어야 통과한다(`len(features) == 29`).
  X1은 스냅샷을 고치지 말고 W1처럼 별도 실험 스크립트에서 `load_data` 결과에 X1 열을 row 키로 붙여 `feature_matrix` 대신
  `full29 + X1` 행렬을 만든다. 분할(component, outer, split1/split2)은 그대로 재사용한다.
- 결측은 LightGBM 기본 NaN 처리. X1 입력 CSV의 SHA-256과 depbee-analyzer 커밋을 실험 manifest에 남긴다.

## D06 추출 준비 상태 (`derived/pairs/baselines.csv`, 데이터 커밋 `be87ab4c`)

| class | old 출처 | new 출처 | 쌍 |
|---|---|---|---:|
| benign | registry | registry | 1,600 |
| hard_benign | registry | registry | 239 |
| malicious | archive | archive | 883 |
| malicious | registry | archive | 45 |

- 정상 1,839쌍은 registry tarball 3,678개를 받아야 한다(이 저장소 checkout에 소스 없음).
- 악성은 데이터 저장소 `pairs/` 아래 원본을 읽는다(정적 읽기만, 실행 금지). 전체 checkout이 필요하다.

### 예상 결측·실패

- 행 전체 실패(errors.csv): registry에서 내려간 버전·tarball, archive 루트 해석 실패, 소스 파일 5,000개 초과 등 로더·수집기 오류.
  D06 데이터 README에 추출 불가 사례가 기록돼 있다(예: 파일 수 초과 1건, `cit-playwright-tests` 루트 문제는 registry로 대체).
- feature 결측: 패키지 밖 파일 실행은 이제 결측이 아니라 `installHookNewExternalExecCount`로 센다.
  `installHookRefFileChanged`의 None은 내부 경로인데 파일이 없는 경우(예: 빌드 산출물이 tarball에 빠짐)에 남는다.
- 정상 패키지도 설치 훅을 새로 넣거나 install 스크립트를 바꾼다(Hard benign 10쌍 점검에서 `installHookNewProgramCount=1`이 흔했다).

## depbee에서 나중에 바꿀 항목 (현재 변경하지 않음)

- 분석기 고정 커밋(`pyproject.toml`의 `depbee-analyzer@917ba90`) 갱신.
- 내장 분석기(`src/depbee/analysis/extractor.py:148`, `resolve_extractors(None)`)에 `code_context`를 명시적으로 추가하거나,
  모델 manifest의 `feature_names`에 따라 필요한 extractor를 고르는 방식.
- feature 스키마 이름(`depbee-features-v1` → v2 등)과 계약 문서(`docs/contracts.md`).
- 모델 manifest: `feature_names`(29+X1 순서), `boolean_features`에 `installHookArgsChanged`·`installHookRefFileChanged`,
  `nullable_features`에 X1 6개 전부.
- 분석 시간 상한: X1은 바뀐 JS 파일마다 old/new를 한 번씩 더 읽고 문자 단위로 훑는다.
