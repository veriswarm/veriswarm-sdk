#!/usr/bin/env bash
# VeriSwarm Guard — fast activity logger (sub-10ms with jq)
# Appends tool-call metadata to ~/.veriswarm/activity.jsonl
# NEVER logs content — only tool name, event type, byte sizes, timestamp.
# Used as a Claude Code hook for PreToolUse and PostToolUse on ALL tools.
#
# Reads the hook payload from stdin: session id from `session_id`, the
# tool result from `tool_response` (falling back to `tool_result`).

set -euo pipefail

LOGFILE="${HOME}/.veriswarm/activity.jsonl"
# Keep in sync with MAX_BUFFER_SIZE in activity_reporter.py.
MAX_BUFFER_SIZE=500
mkdir -p "$(dirname "$LOGFILE")"

INPUT=$(cat)

# Buffer full (uploads failing or not configured): drop rather than grow.
if [ -f "$LOGFILE" ]; then
  LINES=$(wc -l < "$LOGFILE" | tr -d ' ')
  if [ "${LINES:-0}" -ge "$MAX_BUFFER_SIZE" ]; then
    exit 0
  fi
fi

FALLBACK_SID="local-$PPID"

if command -v jq &>/dev/null; then
  echo "$INPUT" | jq -c --arg fallback "$FALLBACK_SID" '{
    ts: (now | todate),
    sid: (.session_id // $fallback),
    event: .hook_event_name,
    tool: .tool_name,
    input_bytes: ((.tool_input // {} | tostring | length) // 0),
    output_bytes: ((.tool_response // .tool_result // "" | tostring | length) // 0)
  }' >> "$LOGFILE" 2>/dev/null || true
else
  echo "$INPUT" | FALLBACK_SID="$FALLBACK_SID" python3 -c "
import json,sys,os
from datetime import datetime,timezone
d=json.load(sys.stdin)
ti=d.get('tool_input') or {}
tr=d.get('tool_response')
if tr is None:
    tr=d.get('tool_result') or ''
e={'ts':datetime.now(timezone.utc).isoformat(),'sid':d.get('session_id') or os.environ['FALLBACK_SID'],'event':d.get('hook_event_name',''),'tool':d.get('tool_name',''),'input_bytes':len(json.dumps(ti)),'output_bytes':len(tr if isinstance(tr,str) else json.dumps(tr))}
open(os.path.expanduser('~/.veriswarm/activity.jsonl'),'a').write(json.dumps(e)+'\n')
" 2>/dev/null || true
fi

exit 0
