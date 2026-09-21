#!/usr/bin/env bash
# Wait for three-cycle generation, verify all four arms, and write the final report.
# Safe to start before Claude quota resets: it only reads the generation counts while waiting.
set -uo pipefail

ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
DS=${DS:-data/inscope_v2.json}
OUT=${OUT:-outputs/inscope}
CYCLES=${CYCLES:-3}
W=${W:-8}
PIDDIR="$OUT/_genlogs"; . scripts/leobench/_procs.sh
pid_write finish_benchmark
LOG="$OUT/_genlogs/finish_benchmark.log"
TARGET=$(python3 -c "import json;print(len(json.load(open('$DS'))) * $CYCLES)")

say() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

successes() {  # $1=agent, $2=batch
  local f="$OUT/generated_code/$1__$2/processed_instances.json"
  [ -f "$f" ] || { echo 0; return; }
  python3 -c "
import json
try: d=json.load(open('$f'))
except Exception: print(0); raise SystemExit
print(sum(1 for v in d.values() if v.get('success')))" 2>/dev/null || echo 0
}

generation_complete() {
  [ "$(successes claude_code claude_raw)" -ge "$TARGET" ] &&
  [ "$(successes claude_code claude_lp)" -ge "$TARGET" ] &&
  [ "$(successes codex codex_raw)" -ge "$TARGET" ] &&
  [ "$(successes codex codex_lp)" -ge "$TARGET" ]
}

say "=== benchmark finalizer started (target $TARGET per batch) ==="
while ! generation_complete; do
  say "waiting: claude $(successes claude_code claude_raw)/$(successes claude_code claude_lp), codex $(successes codex codex_raw)/$(successes codex codex_lp)"
  sleep 300
done

say "generation complete; starting local verification"
while pid_alive verify_local verify_local.sh; do sleep 60; done
CYCLES="$CYCLES" W="$W" DS="$DS" OUT="$OUT" \
  ./scripts/leobench/verify_local.sh >> "$OUT/_genlogs/finish_benchmark_verify.log" 2>&1

missing=0
for spec in claude_code:claude_raw claude_code:claude_lp codex:codex_raw codex:codex_lp; do
  agent=${spec%%:*}; batch=${spec#*:}
  dir="$OUT/generated_code/${agent}__${batch}/scan_results"
  n=$(find "$dir" -maxdepth 1 -name '*_output.json' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$n" -lt "$TARGET" ]; then
    say "!! verification incomplete: $batch $n/$TARGET"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  osascript -e 'display notification "One or more verification batches are incomplete" with title "A.S.E finalizer stopped" sound name "Basso"' 2>/dev/null
  exit 1
fi

say "verification complete; writing three-cycle report"
.venv/bin/python scripts/leobench/report_ase.py \
  --output-dir "$OUT" --dataset "$DS" \
  --markdown inscope_c3.md --csv inscope_cells_c3.csv \
  | tee "$OUT/report_c3.txt"
say "=== benchmark COMPLETE: inscope_c3.md and inscope_cells_c3.csv ==="
osascript -e 'display notification "Three-cycle report is ready" with title "A.S.E benchmark complete" sound name "Glass"' 2>/dev/null
