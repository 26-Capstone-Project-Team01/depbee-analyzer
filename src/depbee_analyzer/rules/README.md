# npm 버전 diff 규칙 스캔

`diff_scan.py`는 같은 패키지의 이전·대상 버전에서 **새로 생긴 행위**를 정적으로 찾는다. 두 버전의 추출된 파일을 읽으며 패키지 코드나 설치 스크립트를 실행하지 않는다. 결과는 모델 feature와 별도인 규칙 판정이다.

| 규칙 | 적중 조건 | 우려사항 |
|---|---|---|
| `R_download_exec` **필수** | 새 설치 훅이 내려받은 파일과 뒤에서 실행한 파일의 경로가 같음 | 정상 설치기도 가능하므로 **검토** |
| `R_secret_send` **필수** | 새 설치 경로에서 자격정보 읽기와 원격 전송이 연결됨 | 알려진 직접 경로만 찾음. 전송 성공은 확인하지 않음 |
| `R_ci_secret_send` | 새 CI 작업의 해독된 명령이 환경·비밀 파일을 원격 전송 | 해당 워크플로가 실제 저장소에서 실행되어야 함 |
| `R_install_root_wipe` | 설치 훅에 `rm -rf --no-preserve-root /` 추가 | 실행·삭제 성공은 권한과 플랫폼에 따라 다름 |
| `R_remote_admin_auth_override` | 원격 명령 봇의 환경변수 인증을 고정 계정으로 교체 | 계정 소유자·변경 승인 여부는 코드만으로 모름. **검토** |
| `R_diff_obfuscation` | 변경 파일의 추가 줄에 디코딩과 `eval`/`Function`이 함께 생김 | 난독화만으로 악성 확정 불가. **검토** |

설치 훅 또는 CI에서 유출·삭제 경로가 보이는 규칙도 **코드 근거**이며 실행 성공이나 침해 경위를 확정하지 않는다. `R_download_exec`, 인증 교체, 난독화는 적중해도 자동 악성 판정에 사용하지 않는다. 검사한 정상→정상 업데이트 140쌍에서는 적중 0건이었지만 오탐이 불가능하다는 뜻은 아니다. 공개 악성 표기 쌍의 평가는 선택된 파일 범위였으므로 미적중을 안전 판정으로 쓰지 않는다.

```bash
python -m depbee_analyzer.rules.diff_scan \
  --normal-dir /path/to/old/package \
  --target-dir /path/to/new/package
```

Python에서는 `from depbee_analyzer.rules.diff_scan import scan_pair, scan_pair_dirs`로 호출한다. `scan_pair`는 상대경로→bytes 맵 두 개를 받고, `scan_pair_dirs`는 두 추출 디렉터리를 받는다. 입력 tarball의 출처·해시 검증과 안전한 추출은 호출 측에서 수행한다. 파일 누락이나 다른 패키지명은 `unknown`으로 표시하며, 이를 음성 판정으로 바꾸지 않는다.
