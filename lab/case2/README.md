# 계정 접속과 파일 접근 합성 실습

17·18장의 CASE-0907 실습 코드다. 실제 사건·제품 로그·실제 전송 파일은 포함하지 않는다.
Python 3.9 이상의 표준 라이브러리만 사용하며 네트워크·인증·모델 호출은 없다.
로그는 결정적으로 생성된다. 실제 제품이나 다른 JSONL 형식에 그대로 적용하지 않는다.

## 실행

명령은 Bash 기준이다. fish에서는 먼저 `bash`로 들어간다. `CASE-0907-A`가 이미
있으면 지우지 말고 새 이름을 사용한다. 생성기와 분석기는 이미 있는 빈 폴더도 거부한다.

```bash
(
set -e
cd ~/handbook-lab
python3 --version
mkdir -p case2/runs
python3 case2/generate.py --out case2/runs/CASE-0907-A
python3 case2/show.py verify-receipt --case case2/runs/CASE-0907-A
python3 case2/analyze.py \
  --evidence case2/runs/CASE-0907-A/evidence \
  --out case2/runs/CASE-0907-A/analysis
python3 case2/show.py summary --analysis case2/runs/CASE-0907-A/analysis
python3 case2/show.py timeline \
  --analysis case2/runs/CASE-0907-A/analysis --instance auth.jsonl:3
python3 case2/test_case2.py
)
```

증거는 새 사건 폴더의 `evidence/`에, 생성 해시 기록은 그 바깥 `receipt.json`에,
분석 결과는 `analysis/`에 생성된다. 기존 랩의 `evidence/`는 변경하지 않는다.
시도한 명령의 종료코드와 출력 파일 존재·입력 해시를 함께 확인한다. 실패한 생성·분석의
부분 폴더가 남아도 덮어쓰지 않는다. 삭제를 자동으로 수행하는 복구 기능은 없다.

## 읽기 순서

`FORMAT.md`에서 필드와 집계 의미를 확인한 뒤 원문을 조사한다. 독립적으로 풀어볼 때는
`INSTRUCTOR.md`와 생성기의 사건 구성 부분을 먼저 읽지 않는다. 모델에게 분석을 맡길
때에도 해설을 입력에 섞지 않으며, 원문·설정·생성기를 수정하거나 네트워크에 연결하게 하지 않는다.
실제 새 프롬프트의 모델 성공 응답을 배포 결과에 포함하지 않았다.

`show.py quote --evidence DIR auth.jsonl:3`은 원문 위치와 해당 물리 행을 표시한다.
`show.py naive --evidence DIR --user account-a`는 의도적으로 사용자명만 집계하는
비교 도구이며, 정식 입력 검사가 끝난 자료에서 조건 누락의 효과를 살펴볼 때만 사용한다.
조회 결과를 공격 판정으로 해석하지 않는다.

기존 랩의 권한 설정이 이 새 경로까지 보호하는지 별도로 확인한다. 프로그램이 읽기만
하도록 작성됐다는 사실과 운영체제의 읽기 전용 통제는 다른 조건이다. 모든 시험은
가상의 자료로 수행하며 실제 회사·개인 증거를 이 실습에 넣지 않는다.
