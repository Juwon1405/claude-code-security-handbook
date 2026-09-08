---
name: triage-line
description: 알림 한 줄을 받아 증거로 확인하고 판정 JSON 을 돌려준다. 근거 라인을 반드시 인용한다.
---

# 알림 한 줄 판정

입력으로 받은 관측 한 줄을 `evidence/` 의 로그로 확인하고 아래 모양으로만 답한다.

1. `evidence/` 에서 그 관측에 해당하는 줄을 찾는다. 못 찾으면 verdict 를 `unknown` 으로 한다.
2. 판정은 malicious / suspicious / benign / unknown 넷 중 하나다.
3. `evidence_line` 에는 찾은 줄을 원문 그대로 한 줄 넣는다. 요약하지 않는다.
4. 자산 목록으로 확인된 우리 자산이면 `asset` 을 true 로 한다.
   자산 여부와 악성 판정은 별도로 판단하며, 내부 자산이라는 이유로
   verdict 를 낮추지 않는다. 우리 자산은 자동 차단 목록에서 제외하고
   대응 여부를 따로 검토한다.

출력 형식:
```json
{
  "verdict": "...",
  "severity": "...",
  "evidence_line": "...",
  "asset": false,
  "reason": "두 문장 이내"
}
```
