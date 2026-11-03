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
# Keep in sync with _lock_path() in activity_reporter.py.
LOCKFILE="${LOGFILE}.lock"
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
  ENTRY=$(echo "$INPUT" | jq -c --arg fallback "$FALLBACK_SID" '{
    ts: (now | todate),
    sid: (.session_id // $fallback),
    event: .hook_event_name,
    tool: .tool_name,
    input_bytes: ((.tool_input // {} | tostring | length) // 0),
    output_bytes: ((.tool_response // .tool_result // "" | tostring | length) // 0)
  }' 2>/dev/null || true)
else
  ENTRY=$(echo "$INPUT" | FALLBACK_SID="$FALLBACK_SID" python3 -c "
import json,sys,os
from datetime import datetime,timezone
d=json.load(sys.stdin)
ti=d.get('tool_input') or {}
tr=d.get('tool_response')
if tr is None:
    tr=d.get('tool_result') or ''
e={'ts':datetime.now(timezone.utc).isoformat(),'sid':d.get('session_id') or os.environ['FALLBACK_SID'],'event':d.get('hook_event_name',''),'tool':d.get('tool_name',''),'input_bytes':len(json.dumps(ti)),'output_bytes':len(tr if isinstance(tr,str) else json.dumps(tr))}
print(json.dumps(e))
" 2>/dev/null || true)
fi

[ -n "${ENTRY:-}" ] || exit 0

# Append under the same flock(2) lock activity_reporter.py holds while it
# drains or rewrites the buffer; an unlocked append can land in a file the
# reporter has already read and deleted. macOS ships no flock(1), so use
# perl's flock there. Last resort (neither available): unlocked append.
if command -v flock &>/dev/null; then
  { flock -x 9; printf '%s\n' "$ENTRY" >> "$LOGFILE"; } 9>>"$LOCKFILE" 2>/dev/null || true
elif command -v perl &>/dev/null; then
  perl -e 'use Fcntl ":flock"; open(my $l, ">>", $ARGV[0]) or exit 0; flock($l, LOCK_EX) or exit 0;
           open(my $f, ">>", $ARGV[1]) or exit 0; print $f "$ARGV[2]\n"; close($f);' \
    "$LOCKFILE" "$LOGFILE" "$ENTRY" 2>/dev/null || true
else
  printf '%s\n' "$ENTRY" >> "$LOGFILE" 2>/dev/null || true
fi

exit 0
