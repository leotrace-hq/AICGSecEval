#!/usr/bin/env bash
# Redact GitHub tokens from the run logs. Waits for the generation orchestrator to exit first:
# sed -i rewrites+renames the file, which would orphan a live tee's fd and silently lose all
# further output. Only safe once nothing is writing.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
PID=${1:-}
if [ -n "$PID" ]; then
  while kill -0 "$PID" 2>/dev/null; do sleep 30; done
fi
sleep 5  # let tee flush and close
n=0
for f in "$ASE"/outputs/*/_genlogs/*.log "$ASE"/agent_gencode_error.log; do
  [ -f "$f" ] || continue
  if grep -aqE 'gh[pousr]_[A-Za-z0-9]{16,}' "$f"; then
    LC_ALL=C sed -i '' -E 's/gh[pousr]_[A-Za-z0-9]{16,}/<REDACTED-GH-TOKEN>/g' "$f"
    echo "[scrub] redacted $f"; n=$((n+1))
  fi
done
echo "[scrub] done @ $(date '+%F %T') — $n file(s) redacted"
