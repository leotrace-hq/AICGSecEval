#!/usr/bin/env bash
# Verify batches locally (QEMU on arm64), sequentially. Usage: verify_local.sh [batch ...]
# Sequential by design: batches share the Docker daemon and the image cache, and A.S.E already
# parallelises inside a batch via --max_workers.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
DS=${DS:-data/inscope_v2.json}; OUT=${OUT:-outputs/inscope}; W=${W:-8}
PIDDIR="$OUT/_genlogs"; . scripts/leobench/_procs.sh
pid_write verify_local
BATCHES=${*:-"claude_raw claude_lp codex_raw codex_lp"}
say() { echo "[$(date '+%F %T')] $*" | tee -a "$OUT/_genlogs/verify_local.log"; }
agent_of() { case "$1" in claude_*) echo claude_code;; codex_*) echo codex;; esac; }

say "=== local verification: $BATCHES ==="
for b in $BATCHES; do
  a=$(agent_of "$b")
  n=$(ls "$OUT/generated_code/${a}__${b}/scan_results"/*.json 2>/dev/null | wc -l | tr -d ' ')
  tot=$(python3 -c "import json;print(len(json.load(open('$DS'))))")
  if [ "$n" -ge "$tot" ]; then say "$b already scanned ($n/$tot) - skipping"; continue; fi
  say "--- $b: scanning ---"
  S=$(date +%s)
  .venv/bin/python invoke.py --run_step security_scan --agent --agent_name "$a" \
    --batch_id "$b" --dataset_path "$DS" --num_cycles 1 --output_dir "$OUT" \
    --max_workers "$W" --github_token unused \
    >> "$OUT/_genlogs/verify_local_${b}.log" 2>&1
  say "$b finished in $(( ($(date +%s)-S)/60 ))m$(( ($(date +%s)-S)%60 ))s (exit $?)"
done
say "=== all requested batches done ==="
osascript -e 'display notification "All batches verified locally" with title "A.S.E verification complete" sound name "Glass"' 2>/dev/null
