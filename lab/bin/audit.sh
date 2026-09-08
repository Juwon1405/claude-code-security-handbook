#!/bin/bash
# PostToolUse 훅. 어떤 도구가 언제 돌았는지 한 줄씩 남긴다.
payload=$(cat)
read -r -d '' PICK <<'PY'
import sys, json
print(json.load(sys.stdin).get("tool_name", ""))
PY
tool=$(printf '%s' "$payload" | /usr/bin/python3 -c "$PICK" 2>/dev/null)
LOG="$CLAUDE_PROJECT_DIR/derived/audit.log"
printf '%s\t%s\n' "$(date -u +%FT%TZ)" "$tool" >> "$LOG"
exit 0
