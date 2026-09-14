#!/bin/bash
# PostToolUse 훅. 성공한 도구의 이름과 시각을 기록한다.
payload=$(cat)
if ! tool=$(printf '%s' "$payload" | jq -ers '
  select(length == 1) | .[0] | select(type == "object")
  | .tool_name | select(type == "string" and length > 0)
  | select(test("[[:cntrl:]]") | not)
'); then
  echo '감사 입력의 도구 이름을 읽지 못했다.' >&2
  exit 1
fi
if [ -z "${CLAUDE_PROJECT_DIR:-}" ]; then
  echo '감사 기록의 프로젝트 경로가 지정되지 않았다.' >&2
  exit 1
fi
LOG="$CLAUDE_PROJECT_DIR/derived/audit.log"
if ! at=$(date -u +%FT%TZ); then
  echo '감사 시각을 읽지 못했다.' >&2
  exit 1
fi
if ! printf '%s\t%s\n' "$at" "$tool" >> "$LOG"; then
  echo '감사 기록을 저장하지 못했다.' >&2
  exit 1
fi
exit 0
