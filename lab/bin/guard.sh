#!/bin/bash
# PreToolUse의 Bash 입력을 검사하는 연습용 훅이다.
payload=$(cat)
if ! cmd=$(printf '%s' "$payload" |
  jq -er '.tool_input.command | select(type == "string")'); then
  echo '훅 입력을 읽지 못해 호출을 차단한다.' >&2
  exit 2
fi

deny() {
  local log="${CLAUDE_PROJECT_DIR:-$PWD}/derived/guard-denials.jsonl"
  if ! printf '%s' "$payload" | jq -c --arg at "$(date -u +%FT%TZ)" '
    {at:$at, session_id, tool_use_id, tool_name,
     reason:"evidence write pattern", command:.tool_input.command}
  ' >> "$log"; then
    echo '차단 기록 저장에 실패했다. 호출 차단은 유지한다.' >&2
  fi
  printf '증거 폴더 쓰기 표현을 차단한다: %s\n' "$cmd" >&2
  exit 2
}
case "$cmd" in
  *"> "*evidence/*)       deny ;;
  *">>"*evidence/*)       deny ;;
  *"rm "*evidence/*)      deny ;;
  *"mv "*evidence/*)      deny ;;
  *"truncate"*evidence/*) deny ;;
esac
exit 0
