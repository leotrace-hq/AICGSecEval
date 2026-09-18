#!/usr/bin/env bash
# Desktop-notify when generation finishes. Usage: notify_done.sh <orchestrator_pid> [out] [ds]
# Reports the real outcome, not just "finished": a run killed by the zero-success guard, or one
# that ends with batches short of the cohort, must not look like a clean completion.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
PID=${1:?need the orchestrator pid}
OUT=${2:-outputs/inscope}; DS=${3:-data/inscope_v2.json}
cd "$ASE"
while kill -0 "$PID" 2>/dev/null; do sleep 30; done
sleep 5

TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")
msg=$(python3 -c "
import json,os
out=[]
for b in ['claude_code__claude_raw','claude_code__claude_lp','codex__codex_raw','codex__codex_lp']:
    f=os.path.join('$OUT','generated_code',b,'processed_instances.json')
    try: d=json.load(open(f)); ok=sum(1 for v in d.values() if v.get('success'))
    except Exception: ok=0
    out.append('%s %d' % (b.split('__')[1], ok))
print(' | '.join(out))")
if grep -aq 'ABORT:' "$OUT/_genlogs/gen.log" 2>/dev/null; then
  title="A.S.E run ABORTED"; sound="Basso"
elif echo "$msg" | grep -qv "$TOTAL"; then
  title="A.S.E generation done (check counts)"; sound="Glass"
else
  title="A.S.E generation complete"; sound="Glass"
fi
osascript -e "display notification \"$msg\" with title \"$title\" subtitle \"of $TOTAL each\" sound name \"$sound\"" 2>/dev/null
echo "[notify] $title -- $msg"
