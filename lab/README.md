# 『터미널에서 시작하는 보안 분석 — Claude Code 실무 핸드북』 실습 파일

이 안내에 따라 실습 폴더를 준비한 뒤 책의 1장으로 돌아가세요. 1장부터 16장까지 쓰는 합성 증거 8종은 생성기로 만듭니다. 17·18·19장과 부록 C에서는 각 실습 폴더에서 별도의 입력을 만듭니다.

## 처음 설치하기

**Windows**에서는 책의 부록 D 「Windows·WSL2에서 실습 준비하기」부터 읽으세요. Windows 다운로드 폴더의 ZIP을 WSL2의 Ubuntu로 복사하고, Ubuntu 홈에 압축을 풀어 파일을 확인합니다. 탐색기에서 이 안내를 열어 보았더라도, 실습 명령은 부록 D에서 안내하는 Ubuntu 터미널에서 실행하세요.

**macOS**에서는 아래 두 경우 가운데 현재 상태에 맞는 방법으로 실습 폴더를 준비하세요.

- **이미 압축을 풀었다면** Finder에서 이 `README.md`와 `SHA256SUMS.txt`가 함께 들어 있는 폴더를 **통째로** 홈 폴더로 옮기고 이름을 `handbook-lab`으로 맞추세요. 숨김 폴더인 `.claude`도 함께 옮겨집니다. 이미 그 위치에 풀었다면 바로 아래의 ‘파일 확인과 데이터 생성’으로 가세요. 홈에 같은 이름의 다른 폴더가 있다면 따로 보관하세요.
- **ZIP을 내려받기만 했다면** 터미널에서 다음 명령을 실행하세요. ZIP을 다운로드 폴더 외의 위치에 저장했다면 `unzip` 뒤의 경로를 바꾸세요.

```bash
(
  set -eu
  mkdir ~/handbook-lab
  unzip ~/Downloads/handbook-lab-files-v2.0.zip -d ~/handbook-lab
)
```

### 파일 확인과 데이터 생성

macOS에서 위 단계가 끝나면 다음 명령을 실행하세요. 배포 파일마다 `OK`가 표시되면 합성 증거 8종을 만듭니다. 검사나 생성 중 오류가 나면 해당 줄의 파일 이름과 경로를 먼저 확인하세요.

```bash
(
  set -eu
  cd ~/handbook-lab
  shasum -a 256 -c SHA256SUMS.txt
  python3 gen_lab_data.py evidence
  chmod +x bin/guard.sh bin/audit.sh
)
```

이제 터미널에서 다음 명령으로 실습 폴더에 들어가세요.

```bash
cd ~/handbook-lab
```

생성한 파일의 행 수·바이트·체크섬은 이 파일의 「생성 데이터 대조표」에서 확인하세요. 같은 자료를 사용해도 모델의 표현과 도구 선택은 달라질 수 있습니다.

생성기와 `lab-manifest.txt`는 `evidence/` 밖에 둡니다. 증거 폴더에는 분석할 데이터만 놓아 모델이 생성기의 설명을 분석 근거로 사용하는 일을 피합니다. 생성기는 증거 폴더·실습 마커·매니페스트가 이미 있으면 덮어쓰지 않고 중단합니다. 처음부터 다시 연습할 때에는 기존 자료를 보관하고 새 실습 폴더를 준비합니다. 실제 사건 자료나 개인 자료가 있는 폴더는 지정하지 않습니다.

`processes.csv`의 배경 행은 실제 Windows 프로세스 계보 전체를 재현한 자료가 아니며, 관계 대조 실습은 `1520 → 5820 → 5896`을 대상으로 PID뿐 아니라 호스트와 시각도 함께 확인합니다.

## 기준 환경

- macOS Apple Silicon에서 확인했습니다. 셸 예제는 bash·zsh 기준입니다. fish에서는 bash를 연 뒤 실행합니다. macOS의 zsh에서는 터미널을 열 때마다 `setopt interactivecomments`를 먼저 입력해, 명령에 붙은 `#` 주석이 명령으로 해석되지 않게 합니다.
- 책의 화면과 다르면 해당 장의 버전 설명을 확인하세요. 부록 D에는 운영체제별로 확인한 범위를 정리했습니다.
- 생성기는 Python 3 표준 라이브러리만 사용합니다. macOS·Ubuntu·Windows ARM64에서 UTF-8·LF로 생성되는지 확인했으며, 같은 묶음의 파일별 체크섬으로 결과를 대조합니다.
- jq, shasum과 기본 셸 도구가 필요합니다. 8장의 구조 검증에는 jsonschema를 추가로 설치합니다.
- Windows 독자는 부록 D의 WSL2·Ubuntu 준비 절차에서 시작합니다. 준비 뒤에는 Ubuntu 터미널에서 본문 명령을 이어갑니다. Windows ARM64에서 확인한 범위는 Python 합성 데이터와 실행 조건을 갖춘 오프라인 시험이며, WSL2의 전체 실습과 네이티브 Windows의 Bash 샌드박스까지 확인한 것은 아닙니다.
- 모델 호출에는 계정의 요금과 사용량 제한이 적용됩니다. 예제의 호출별 예산 상한이 책 전체 비용을 보장하지는 않습니다.

## 8장 검증용 Python 환경

운영체제의 Python 패키지를 바꾸지 않도록 가상환경을 권장합니다. 가상환경 생성에 사용할 `python3`가 설치되어 있어야 합니다.

```bash
cd ~/handbook-lab
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install 'jsonschema>=4,<5'
python3 -c 'import jsonschema; print("jsonschema ready")'
```

8장 코드를 실행할 터미널에서도 같은 가상환경을 활성화합니다. 실습 후 `deactivate`로 빠져나올 수 있습니다. 패키지를 설치한 Python과 배치에서 부른 Python이 다르면 설치했어도 모듈을 찾지 못합니다.

8장의 `bin/validate_verdict.py`는 응답 JSON, 판정 스키마, 원본 로그를 이 순서로 받습니다.

```bash
python3 bin/validate_verdict.py out/response.json \
  bin/verdict.schema.json evidence/access.log
```

`out/response.json`은 검사할 실제 응답 파일로 바꿉니다. 통과하면 원문 파일과 행 번호를 출력하고 종료코드 0을 반환합니다. 오류가 있으면 stderr에 이유를 적고 1로 종료합니다. 인용의 CR·LF·NUL을 거부하며, 원본 한 줄의 앞뒤 공백은 보존해 대조합니다. 인용이 존재해도 판정의 타당성은 따로 검토해야 합니다. 검사기 전문은 책 부록 A에 있습니다.

## 생성 데이터 대조표

표와 생성기의 `lab-manifest.txt`는 읽기 편하도록 SHA-256 앞 16자리를 표시합니다. 아래 명령으로 전체 해시를 계산하고 앞 16자리를 대조합니다. 별도로 보존하는 조사 전후 검증 기록에는 전체 해시를 남깁니다. 모델이 요약한 값 대신 명령 출력으로 비교합니다.

| 파일 | 행수 | 바이트 | SHA-256 앞 16자리 |
|---|---|---|---|
| `access.log` | 16,952 | 3,800,043 | `66aa1efec3b7f95f` |
| `auth.log` | 1,706 | 259,383 | `105ba126478b3c9a` |
| `winlog.jsonl` | 3,381 | 620,347 | `ee0a7be5c82983bb` |
| `conn.log` | 12,089 | 1,205,535 | `dba1919c869a99fa` |
| `dns.log` | 9,215 | 710,360 | `60041504d7323648` |
| `processes.csv` | 1,201 | 119,313 | `c438683328b5494d` |
| `suspicious.ps1` | 28 | 1,710 | `130543f4e134e152` |
| `iocs_messy.txt` | 16 | 528 | `2cdc955a45ed8aaf` |

```bash
wc -l evidence/*.log evidence/*.jsonl evidence/*.csv \
      evidence/*.ps1 evidence/*.txt
shasum -a 256 evidence/*.log evidence/*.jsonl evidence/*.csv \
             evidence/*.ps1 evidence/*.txt
```

값이 다르면 파일 경로, 생성기 버전, 인코딩과 줄바꿈, 이전 실습에서 파일을 수정했는지부터 확인합니다. 원인을 확인하지 않은 채 증거 폴더를 삭제하지 않습니다. 새 임시 폴더에 생성한 결과와 비교하면 기존 자료를 보존하면서 차이를 찾을 수 있습니다.

## 포함된 파일

| 파일 | 사용하는 장 | 역할 |
|---|---|---|
| `gen_lab_data.py` | 3장 | 합성 증거 8종 생성기, 시드 20260901 |
| `.claude/settings.json` | 4장 | 4장의 출발 설정이다. 증거 읽기와 지정한 셸 명령을 허용하고 비밀 파일 읽기와 일부 명령을 거부한다. 목록에 없는 쓰기에는 추가 승인이 필요할 수 있다. 이 파일만으로 증거 쓰기 차단을 보장하지 않는다. |
| `settings.hardened.json` | 13장 | 13장의 강화 설정이다. 증거 경로 편집과 비밀 파일 읽기를 제한하고, 일부 외부 조회 도구를 제외한다. 샌드박스가 적용되지 않으면 실행을 중단하도록 설정하며, 사용 전 실제 허용·거부 동작을 시험한다. |
| `triage-rules.txt` | 6장 | 판정 기준과 인용 방식을 전달하는 파일이다. --append-system-prompt-file 로 지정해 사용하며, 지침이 포함됐더라도 실제 인용과 자산 분류가 맞는지는 응답마다 확인한다. |
| `untrusted-rules.txt` | 9장 | 신뢰하지 않는 자료를 데이터로 취급하고 그 안의 지시를 따르지 않도록 안내한다. 지침만으로 실행을 막을 수는 없으므로 9장의 도구 제한과 설정 제외를 함께 적용한다. |
| `bin/structured-rules.txt` | 8장 | 8장에서 구조화된 응답을 요청할 때 사용하는 지침이다. evidence_line에는 로그 원문만 넣고 파일명 등 출처는 reason에 적도록 안내한다. 형식을 만족한 응답도 실제 원문과 자산 분류를 별도로 확인한다. |
| `ioc-rules.txt` | 9장 | IOC의 방어형 표기 해제, 중복 병합, 유형 분류, 해시 소문자화와 자산 구분을 안내한다. 정규화한 결과는 원문과 대조하며, 자산 여부가 확인되지 않은 주소를 자동 차단에 사용하지 않는다. |
| `bin/verdict.schema.json` | 8장 | 다섯 필드로 구성된 판정 형식을 정의한다. --json-schema 로 전달하며, 반환 객체가 스키마를 만족하는지와 판정 내용이 근거에 부합하는지는 별도로 검사한다. |
| `bin/validate_verdict.py` | 8장 | 응답 JSON의 정상 상태와 판정 스키마를 검사하고, 줄바꿈·NUL이 없는 인용을 원본 로그의 한 줄과 직접 대조한다. 일치한 파일·행 번호를 출력하며 판정의 타당성은 별도 검토한다. |
| `bin/alerts.txt` | 8장 | 배치 입력 파일이다. 한 줄에 알림 하나를 적으며, 8장의 루프는 각 줄을 차례로 처리한다. |
| `alerts/a1-webshell.log` | 7장 | 트리아지 루프의 입력이며 파일 하나에 알림 하나가 들어간다. 7장의 루프는 alerts/*.log에 해당하는 파일을 하나씩 처리한다. |
| `alerts/a2-404-burst.log` | 7장 | 두 번째 알림 파일이며 위와 같은 폴더에 둔다. |
| `bin/guard.sh` | 14장 | PreToolUse에 연결하는 문자열 검사 예제다. 입력 오류와 일치하는 쓰기 표현을 exit 2로 거부하고, 패턴에 걸린 호출의 ID·명령을 별도 JSONL에 기록한다. 모든 셸 표현을 해석하지는 않으므로 읽기 전용 경계와 함께 사용한다. |
| `bin/audit.sh` | 14장 | PostToolUse에서 성공한 도구 호출의 이름과 UTC 시각을 기록한다. 입력 오류나 기록 실패는 오류로 알리지만 이미 끝난 호출을 되돌리지는 못한다. 차단된 시도나 명령 전체를 포함하는 기록은 아니다. |
| `no-hook.settings.json` | 14장 | 훅을 달기 전의 비교 설정이다. 지정한 셸 명령과 임시 시험 파일의 쓰기를 허용하므로 14장의 격리된 실습 폴더에서만 사용한다. |
| `hooked.settings.json` | 14장 | 비교 설정과 같은 권한·샌드박스에 차단·감사 훅만 더한 설정이다. guard.sh와 audit.sh를 모두 준비한 뒤 임시 복제본에서 사용한다. |
| `examples/ch15/CLAUDE.md` | 15장 | 케이스의 공통 지침 예시다. 15장에서 폴더 최상단의 CLAUDE.md로 복사한다. 원문 인용과 UTC 표기를 전달하는 문서이며 파일 접근을 강제하는 설정은 아니다. |
| `examples/ch15/skills/triage-line/SKILL.md` | 15장 | 알림을 근거와 대조해 판정 JSON을 반환하는 스킬이다. 자산 분류와 악성 판단을 구분하며, 15장에서 .claude/skills/triage-line/SKILL.md로 복사한 뒤 호출과 근거를 검증한다. |
| `examples/ch15/agents/log-reader.md` | 15장 | 별도 컨텍스트에서 필요한 로그를 조회하는 서브에이전트다. 읽기와 검색 도구만 허용하며, 15장에서 .claude/agents/log-reader.md로 복사한 뒤 원문과 컨텍스트 증가량을 확인한다. |
| `test_safety.py` | 3·14장 | 기존 자료 보존·UTF-8/LF 재현과 차단·감사 훅의 오류 처리를 시험한다. |
| `bin/triage-batch.sh` | 7장 | 알림 파일을 하나씩 호출하고 입력별 상태와 보고 비용을 집계하는 배치 스크립트다. 본문 7장의 코드와 같다. |
| `case2/generate.py` | 17장 | 계정·파일·전송 기록 3종을 새 사건 폴더에 생성한다. |
| `case2/analyze.py` | 17~18장 | 형식·중복·세션 구간을 검사하고 근거가 연결된 결과를 만든다. |
| `case2/show.py` | 17~18장 | 입력 해시, 원문 인용, 집계와 타임라인을 조회한다. |
| `case2/test_case2.py` | 18장 | 고정 결과와 잘못된 입력의 거부를 독립 시험한다. |
| `case2/FORMAT.md` | 17~18장 | 자체 JSONL 형식과 필드·연결·집계의 의미를 설명한다. |
| `case2/README.md` | 17~18장 | 새 사건의 생성과 분석 순서를 안내한다. |
| `case2/INSTRUCTOR.md` | 17~18장 | 사건 구성과 해설이다. 독립 분석을 마친 뒤 대조한다. |
| `recovery/recover.py` | 19장 | 여섯 모의 실행을 만들고 입력·응답·인용 상태를 분류한다. |
| `recovery/test_recover.py` | 19장 | 정상 분류와 오류 입력을 시험하고 의미 검토의 한계를 확인한다. |
| `foundations/generate.py` | 부록 C | 셸·JSON 연습용 작은 입력 12개를 새 폴더에 생성한다. |
| `foundations/check_inputs.py` | 부록 C | 기초 실습 전후 입력 해시를 대조한다. |
| `foundations/validate_jsonl.py` | 부록 C | UTF-8과 JSONL의 줄별 문법을 확인한다. |
| `foundations/to_utc.py` | 부록 C | 오프셋을 명시한 연습용 시각을 UTC로 변환한다. |
| `foundations/test_foundations.py` | 부록 C | 기초 실습의 출력과 실패 조건을 독립 시험한다. |
| `foundations/README.md` | 부록 C | 기초 실습의 준비와 입력 범위를 안내한다. |
| `platform/preflight.py` | 부록 D | 경로 범주·도구 유무·지원 파일을 읽기 전용으로 점검한다. 실습 통과를 판정하지 않는다. |
| `README.md` | — | 설치·검증·오류 대응 안내 |
| `SHA256SUMS.txt` | — | 배포 파일의 전체 SHA-256 목록 |

`.claude/settings.json`은 4장의 출발형입니다. 이 설정만으로 증거 쓰기가 모두 차단되지는 않습니다. 4장의 중간형과 13장의 `settings.hardened.json`을 비교하며 제한을 추가합니다.

15장의 규칙·스킬·서브에이전트 예시는 `examples/ch15/`에 있습니다. 15장 전에는 이를 프로젝트 최상단의 `CLAUDE.md`, `.claude/skills/`, `.claude/agents/`로 복사하지 않습니다. 15장의 각 절에서 기존 파일을 덮어쓰지 않는 명령으로 하나씩 배치한 뒤 새 세션에서 읽힌 내용을 확인합니다. 개인 홈의 규칙이나 설정은 옮기거나 삭제하지 않습니다.

`examples/`는 접근이 차단된 폴더가 아닙니다. 모델에 예시나 생성기·해설을 읽게 하면 아직 배우지 않은 지침이나 답이 분석에 영향을 줄 수 있습니다. 5장에서는 먼저 프로젝트 규칙의 배치 여부를 확인하고, 세션에서 실제로 읽힌 지침도 기록합니다.

`no-hook.settings.json`과 `hooked.settings.json`은 14장의 임시 복제 실습에서 비교하는 설정입니다. 두 파일의 권한·샌드박스 설정은 같고, 후자에만 차단·감사 훅이 있습니다. 훅이 없는 설정으로 대조한 뒤 훅이 있는 설정의 동작을 확인합니다.

`hooked.settings.json`은 `bin/guard.sh`와 `bin/audit.sh`를 모두 준비하고 실행 권한을 확인한 뒤 사용합니다. 두 설정 모두 시험 파일 쓰기를 포함하므로 실제 조사 프로파일로 사용하지 않습니다.

규칙 파일과 스킬은 모델에게 절차를 전달하는 문서이며 보안 차단 장치가 아닙니다. 내부 자산이라는 이유로 악성 판정을 낮추지 않습니다. 자산 목록 확인 여부, 판정 근거, 자동 차단 대상 여부를 구분해 사람이 검토합니다. `log-reader`의 도구는 Read·Grep·Glob으로 제한했습니다.

## 종합 사례와 작은 독립 실습

17~18장에서는 `case2` 폴더에 있는 두 문서를 읽고 17장의 순서대로 새 사건 폴더를 만듭니다. 아래에는 압축을 푼 폴더에서 열 파일과 웹에서 같은 문서를 읽을 수 있는 주소를 함께 적었습니다.

**계정 접속과 파일 접근 실습** · `case2/README.md`

https://github.com/Juwon1405/claude-code-security-handbook/blob/main/lab/case2/README.md

**입력·출력 명세** · `case2/FORMAT.md`

https://github.com/Juwon1405/claude-code-security-handbook/blob/main/lab/case2/FORMAT.md

이 실습에서는 인증·파일 접근·전송 기록을 담은 JSONL 파일 3개를 생성하고, 분석 결과는 증거 폴더 밖에 저장합니다. 같은 이름의 계정과 재사용된 세션, 중복된 이벤트, 전송 상태와 미확인 바이트를 구분해 보세요.

**사건 풀이와 검산** · `case2/INSTRUCTOR.md`. 독립 분석을 마친 뒤에 열어 보세요. 해설은 모델 입력에 포함하지 않습니다.

https://github.com/Juwon1405/claude-code-security-handbook/blob/main/lab/case2/INSTRUCTOR.md

19장의 `recovery/`는 실제 모델을 호출하지 않고 여섯 모의 실행 자료를 만듭니다.
`ready_for_review`는 사람이 내용을 검토할 준비가 됐다는 뜻이며, 악성 여부나 조사 완료를
판정하지 않습니다. 본문의 명령을 같은 Bash에서 순서대로 실행하고 준비·감사 실패 시 중단합니다.

부록 C의 **로그 분석 기초 실습**에서는 작은 입력 파일 12개로 셸과 JSON을 연습합니다. 압축을 푼 폴더에서 `foundations/README.md`를 여세요. 웹에서는 아래 주소에서 같은 안내를 읽을 수 있습니다.

https://github.com/Juwon1405/claude-code-security-handbook/blob/main/lab/foundations/README.md

부록 D의 `platform/preflight.py`는
도구 유무와 정해진 지원 파일을 읽는 진단기이며, Windows 실습이나 실제 샌드박스 차단이
검증됐다고 판정하지 않습니다.

이 독립 실습의 생성·분석·오류 분류에는 네트워크나 모델 호출이 필요하지 않습니다.
17~18장에 실은 대화형 프롬프트는 별도의 작성 예이며, 실제 모델에 입력한다면 계정의
사용량과 자료 취급 조건을 확인하고 응답을 원문과 다시 대조합니다.

오프라인 단위시험은 다음 명령으로 실행합니다. `skipped`는 필요한 도구나 권한이 없어 실행하지 않은 항목이며 통과 건수에 포함하지 않습니다. 이 시험은 실제 모델의 답이나 Claude Code 안의 도구 호출을 검증하지 않습니다.

```bash
python3 case2/test_case2.py
python3 recovery/test_recover.py
python3 foundations/test_foundations.py
python3 test_safety.py
```

## 오류가 났을 때

문서용 예약은 도메인의 비존재나 접속 불가를 뜻하지 않습니다. `suspicious.ps1`의 예제 주소는 외부 조회·접속 없이 정적 분석에만 사용합니다. 예시 도메인의 용도는 IANA의 설명을 참고하세요.

https://www.iana.org/help/example-domains

| 증상 | 확인할 내용 |
|---|---|
| `zsh: command not found: #` | zsh가 주석을 명령으로 해석한 것입니다. `setopt interactivecomments`를 입력한 뒤 해당 블록의 결과를 확인하고 필요하면 다시 실행합니다. |
| 배포 파일 체크섬 FAILED | 실습 폴더에서 검사했는지 확인하세요. 불일치가 계속되면 새로 받은 ZIP을 빈 폴더에 풀어 해당 파일을 대조하세요. |
| 생성 데이터의 행수·해시 불일치 | 생성기와 출력 경로를 확인하고 새 임시 폴더의 결과와 비교합니다. |
| 프로젝트가 신뢰되지 않았다는 안내 | 자신이 만든 실습 폴더인지 먼저 확인합니다. 9장의 신뢰·설정 출처 차이를 읽고 필요한 범위만 승인합니다. |
| 샌드박스 시작 실패 | 운영체제 지원 여부와 의존 패키지, `/sandbox`의 진단을 확인합니다. 제한을 끄고 계속 진행하지 않습니다. |
| 훅이 실행되지 않음 | 실행 권한, 설정 경로, `$CLAUDE_PROJECT_DIR`, 훅 이벤트와 출력 기록을 확인합니다. |
| 8장 결과가 failed/로 분리됨 | 종료코드와 stderr, JSON의 오류 필드, 스키마와 원문 일치 검증을 순서대로 확인합니다. 429나 예산 초과는 성공이 아닙니다. |
| jsonschema를 찾지 못함 | 활성화한 가상환경과 실제 `python3` 경로를 확인합니다. |
| 모델의 답이 화면과 다름 | 답의 문장보다 입력 범위와 원문 근거를 비교합니다. 근거가 없는 단정은 수정하거나 보류합니다. |

## 자료와 정정 안내

실습 ZIP 내려받기

https://github.com/Juwon1405/claude-code-security-handbook/releases/download/v2.0/handbook-lab-files-v2.0.zip

책이나 실습에서 오류를 발견하면 아래 게시판에 장·절과 확인한 내용을 남겨 주세요.

https://github.com/Juwon1405/claude-code-security-handbook/issues

## 사용과 공유

파일의 저작권은 저자 방주원에게 있습니다. 독자는 자기 학습과 실습을 위해 사용·수정할 수 있습니다. 재배포나 교육 자료에 포함하려는 경우에는 저자에게 문의해 주세요.

예제의 문서용 IP 주소와 예약 도메인은 실제 조사 대상이 아닙니다. 외부 조회·접속·차단 장비 등록에 사용하지 않습니다. 정정 의견에는 버전, 운영체제, 장·절과 재현 절차만 적고 실제 사건 자료나 인증 토큰은 보내지 않습니다.
