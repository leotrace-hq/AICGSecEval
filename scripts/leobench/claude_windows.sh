#!/usr/bin/env bash
# Finish the Claude batches across successive subscription rate-limit windows.
#
# The Claude five-hour window allows roughly 38 instances; the cohort needs 134 Claude sessions
# (67 raw + 67 leoprevent), so it takes several windows. This waits for each reset, runs what it
# can, and stops when both batches are complete.
#
# TWO HARD CONSTRAINTS:
#  1. Batches must never run concurrently. They share per-instance repo clones and race on
#     os.makedirs(raw_repo_dir) in invoke.py. So wait for any running orchestrator to exit first.
#  2. run25_gen.sh's zero-success guard exits 1 when a batch records no successes. During a spent
#     window that is EXPECTED, not fatal -- so a non-zero exit here means "wait", and only a
#     genuine auth failure is treated as fatal.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
DS=${DS:-data/inscope_v2.json}
CTX=${CTX:-data/inscope_context.json}
OUT=${OUT:-outputs/inscope}
PIDDIR="$OUT/_genlogs"; . scripts/leobench/_procs.sh
pid_write claude_windows
LOG="$OUT/_genlogs/claude_windows.log"
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")

say() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

successes() {  # $1=batch
  local f="$OUT/generated_code/claude_code__$1/processed_instances.json"
  [ -f "$f" ] || { echo 0; return; }
  python3 -c "
import json
try: d=json.load(open('$f'))
except Exception: print(0); raise SystemExit
print(sum(1 for v in d.values() if v.get('success')))" 2>/dev/null || echo 0
}

resets_at() {  # newest five_hour resetsAt across the claude logs; empty if unknown
  python3 - <<'PY' 2>/dev/null
import re,glob
best=0
for f in glob.glob('outputs/inscope/_genlogs/claude_*.log'):
    try: t=open(f,errors='replace').read()
    except OSError: continue
    for m in re.finditer(r"'five_hour': \{'utilization': [0-9.]+, 'resetsAt': (\d+)\}", t):
        best=max(best,int(m.group(1)))
print(best or '')
PY
}

auth_broken() {  # a genuine auth failure, as distinct from a spent quota
  grep -aqE 'oauth_org_not_allowed|organization has disabled' "$OUT/_genlogs/claude_raw.log" \
       "$OUT/_genlogs/claude_lp.log" 2>/dev/null
}

say "=== claude window scheduler starting (need $TOTAL per batch) ==="

# Constraint 1: never overlap with another orchestrator.
while pid_alive run25_gen run25_gen.sh; do
  say "another batch run is active; waiting for it to finish before touching Claude"
  sleep 120
done

attempt=0
while :; do
  r=$(successes claude_raw); l=$(successes claude_lp)
  say "progress: claude_raw $r/$TOTAL, claude_lp $l/$TOTAL"

  # Completion is checked BEFORE any wait. Ordering these the other way round made the finished
  # run on 2026-09-18 sleep 98 minutes past 22:33 before announcing it was done.
  if [ "$r" -ge "$TOTAL" ] && [ "$l" -ge "$TOTAL" ]; then
    say "=== both Claude batches COMPLETE ==="
    osascript -e "display notification \"claude_raw $r/$TOTAL, claude_lp $l/$TOTAL\" with title \"A.S.E Claude arms complete\" sound name \"Glass\"" 2>/dev/null
    exit 0
  fi

  # Don't burn a pass through the cohort against a window we already know is spent.
  w=$(python3 scripts/leobench/_window_wait.py "$OUT/_genlogs" 2>/dev/null || echo 0)
  if [ "${w:-0}" -gt 0 ]; then
    say "current window still spent; sleeping $((w/60)) min (until $(date -r $(( $(date +%s) + w )) '+%F %T'))"
    sleep "$w"
    continue
  fi

  attempt=$((attempt+1))
  say "--- window attempt $attempt: running claude_raw then claude_lp ---"
  BATCHES="claude_raw claude_lp" DS="$DS" CTX="$CTX" OUT="$OUT" \
    ./scripts/leobench/run25_gen.sh >> "$OUT/_genlogs/gen_claude_w${attempt}.log" 2>&1
  rc=$?
  say "run25_gen.sh exited $rc"

  if auth_broken; then
    say "!! AUTH FAILURE (org policy / bad token), not a quota wall -- stopping for a human"
    osascript -e 'display notification "Claude auth is broken, not just rate-limited" with title "A.S.E run STOPPED" sound name "Basso"' 2>/dev/null
    exit 1
  fi

  r=$(successes claude_raw); l=$(successes claude_lp)
  if [ "$r" -ge "$TOTAL" ] && [ "$l" -ge "$TOTAL" ]; then continue; fi

  ts=$(resets_at)
  now=$(date '+%s')
  if [ -n "$ts" ] && [ "$ts" -gt "$now" ]; then
    wait_s=$(( ts - now + 120 ))            # small buffer past the reset
  else
    wait_s=1800                             # unknown reset: re-check in 30 min
    say "reset time unknown; backing off ${wait_s}s"
  fi
  say "quota window spent; sleeping $((wait_s/60)) min until $(date -r $((now+wait_s)) '+%F %T')"
  sleep "$wait_s"
done
