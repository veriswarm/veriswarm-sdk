#!/usr/bin/env bash
# VeriSwarm Guard — fast activity logger (sub-10ms with jq)
# Appends tool-call metadata to ~/.veriswarm/activity.jsonl
# NEVER logs content — only tool name, event type, byte sizes, timestamp.
# Used as a Claude Code hook for PreToolUse and PostToolUse on ALL tools.

set -euo pipefail

LOGFILE="${HOME}/.veriswarm/activity.jsonl"
mkdir -p "$(dirname "$LOGFILE")"

INPUT=$(cat)

SESSION_ID="${CLAUDE_SESSION_ID:-local-$$}"

if command -v jq &>/dev/null; then
  echo "$INPUT" | jq -c --arg sid "$SESSION_ID" '{
    ts: (now | todate),
    sid: $sid,
    event: .hook_event_name,
    tool: .tool_name,
    input_bytes: ((.tool_input // {} | tostring | length) // 0),
    output_bytes: ((.tool_result // "" | tostring | length) // 0)
  }' >> "$LOGFILE" 2>/dev/null
else
  echo "$INPUT" | python3 -c "
import json,sys,os
from datetime import datetime,timezone
d=json.load(sys.stdin)
ti=d.get('tool_input') or {}
tr=d.get('tool_result') or ''
e={'ts':datetime.now(timezone.utc).isoformat(),'sid':os.environ.get('CLAUDE_SESSION_ID','local-'+str(os.getpid())),'event':d.get('hook_event_name',''),'tool':d.get('tool_name',''),'input_bytes':len(json.dumps(ti)),'output_bytes':len(str(tr) if not isinstance(tr,dict) else json.dumps(tr))}
open(os.path.expanduser('~/.veriswarm/activity.jsonl'),'a').write(json.dumps(e)+'\n')
" 2>/dev/null
fi

exit 0
