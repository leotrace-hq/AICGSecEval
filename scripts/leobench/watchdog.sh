#!/usr/bin/env bash
# Restart claude_windows.sh if it dies while Claude work remains. Exits once both Claude
# batches are complete, so it does not linger. Detached (ppid 1), survives the session.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
OUT=${OUT:-outputs/inscope}
DS=${DS:-data/inscope_v2.json}
LOG="$OUT/_genlogs/watchdog.log"
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")
say() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

successes() {
  local f="$OUT/generated_code/claude_code__$1/processed_instances.json"
  [ -f "$f" ] || { echo 0; return; }
  python3 -c "
import json
try: d=json.load(open('$f'))
except Exception: print(0); raise SystemExit
print(sum(1 for v in d.values() if v.get('success')))" 2>/dev/null || echo 0
}

say "watchdog started (need $TOTAL per Claude batch)"
while :; do
  r=$(successes claude_raw); l=$(successes claude_lp)
  if [ "$r" -ge "$TOTAL" ] && [ "$l" -ge "$TOTAL" ]; then
    say "both Claude batches complete ($r/$l) - watchdog exiting"
    exit 0
  fi
  if ! pgrep -f "bash ./scripts/leobench/claude_windows.sh" >/dev/null; then
    # Do not start while another orchestrator holds the repo clones; claude_windows.sh has the
    # same guard, but starting it into a race and relying on its internal wait is sloppier.
    if pgrep -f "bash ./scripts/leobench/run25_gen.sh" >/dev/null; then
      say "scheduler absent but another batch run is active - holding off"
    else
      say "scheduler NOT running with work left (raw $r/$TOTAL, lp $l/$TOTAL) - restarting it"
      nohup ./scripts/leobench/claude_windows.sh >> "$OUT/_genlogs/claude_windows_stdout.log" 2>&1 &
      sleep 10
      pgrep -f "bash ./scripts/leobench/claude_windows.sh" >/dev/null \
        && say "restarted ok (pid $(pgrep -f 'bash ./scripts/leobench/claude_windows.sh' | head -1))" \
        || say "RESTART FAILED"
    fi
  fi
  sleep 300
done
