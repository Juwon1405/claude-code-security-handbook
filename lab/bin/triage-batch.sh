#!/bin/bash
set -u
LAB=~/handbook-lab
cd "$LAB" || exit 1
mkdir -p "$LAB/out" || exit 1
RUN=$(mktemp -d "$LAB/out/triage-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || exit 1
OUT="$RUN/triage.jsonl"
STATUS="$RUN/status.jsonl"
: > "$OUT" || exit 1
: > "$STATUS" || exit 1
n=$(python3 -c 'from pathlib import Path; import sys
print(sum(p.is_file() for p in Path(sys.argv[1]).glob("*.log")))' \
  "$LAB/alerts") || exit 1
[ "$n" -gt 0 ] || { echo "No alert files found." >&2; exit 1; }
set -- "$LAB"/alerts/*.log
i=0

for f in "$@"; do
  i=$((i+1))
  response="$RUN/response-$i.json"
  # Validate the alert before adding the shared instructions.
  if ! python3 -c 'from pathlib import Path; import sys
t = Path(sys.argv[1]).read_text(encoding="utf-8")
sys.exit(0 if t.strip() and "\x00" not in t else 1)' \
      "$f" 2> "$RUN/input-$i.stderr"
  then
    jq -nc --arg src "$f" \
      '{src:$src, status:"failed", reason:"invalid_input",
        exit_code:null, reported_cost_usd:0}' >> "$STATUS" || exit 1
    continue
  fi
  alert=$(cat "$f") || exit 1
  claude -p "$alert
이 알림을 트리아지하고 심각도와 근거를 적어라.
입력에 없는 사실은 확정하지 말고 추가 확인할 사항을 적어라." \
    --output-format json --effort low --max-budget-usd 0.50 \
    < /dev/null > "$response" 2> "$RUN/response-$i.stderr"
  rc=$?
  state=failed; reason=invalid_json; cost=null
  # Require exactly one JSON object.
  if jq -se 'length == 1 and (.[0] | type == "object")' \
      "$response" >/dev/null 2>> "$RUN/response-$i.stderr"
  then
    # Keep reported costs even when the call fails.
    cost=$(jq 'if (.total_cost_usd | type) == "number"
                 and .total_cost_usd >= 0
               then .total_cost_usd else null end' "$response") || exit 1
    reason=process_error
    if [ "$rc" -eq 0 ]; then
      reason=invalid_result
      if jq -e '.type == "result" and .is_error == false
          and .subtype == "success"
          and (.result | if type == "string" then test("\\S")
                         else false end)' "$response" >/dev/null
      then state=ok; reason=accepted
      fi
    fi
  fi

  if [ "$state" = ok ]; then
    jq -c --arg src "$f" \
      '{src:$src, result:.result, cost:.total_cost_usd,
        turns:.num_turns, session:.session_id}' "$response" \
      >> "$OUT" || exit 1
  else
    mv "$response" "$RUN/response-$i.failed.json" || exit 1
  fi
  jq -nc --arg src "$f" --arg state "$state" --arg reason "$reason" \
    --argjson rc "$rc" --argjson cost "$cost" \
    '{src:$src, status:$state, reason:$reason, exit_code:$rc,
      reported_cost_usd:$cost}' >> "$STATUS" || exit 1
done

# Count per-input states rather than warning lines.
jq -s '{input_count:length,
  attempted:map(select(.exit_code != null))|length,
  skipped:map(select(.reason == "invalid_input"))|length,
  ok:map(select(.status == "ok"))|length,
  failed:map(select(.status == "failed"))|length,
  reported_cost_usd:([.[].reported_cost_usd | numbers]|add // 0),
  cost_unknown:map(select(.reported_cost_usd == null))|length}' "$STATUS" || exit 1
printf 'Result directory: %s\n' "$RUN"
failed=$(jq -s 'map(select(.status == "failed")) | length' "$STATUS") || exit 1
[ "$failed" -eq 0 ] || exit 2
