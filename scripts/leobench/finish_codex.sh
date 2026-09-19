#!/usr/bin/env bash
# Retry whatever the Codex batches are still missing, once nothing else holds the repo clones.
# Individual Codex instances fail transiently ("调用Agent处理返回失败"); A.S.E never records a
# failure, so simply re-running the batch picks up exactly the gaps.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
DS=${DS:-data/inscope_v2.json}; CTX=${CTX:-data/inscope_context.json}
OUT=${OUT:-outputs/inscope}; CYCLES=${CYCLES:-3}
PIDDIR="$OUT/_genlogs"; . scripts/leobench/_procs.sh
pid_write finish_codex
LOG="$OUT/_genlogs/finish_codex.log"
say() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
TARGET=$(python3 -c "import json;print(len(json.load(open('$DS'))) * $CYCLES)")

missing() {  # $1=batch -> how many entries short of TARGET
  python3 -c "
import json,os
f='$OUT/generated_code/codex__$1/processed_instances.json'
n=len(json.load(open(f))) if os.path.exists(f) else 0
print(max(0, $TARGET - n))" 2>/dev/null || echo "$TARGET"
}

say "=== codex gap-filler starting (target $TARGET per batch) ==="
for pass in 1 2 3; do
  gaps=0
  for b in codex_raw codex_lp; do m=$(missing "$b"); gaps=$((gaps+m)); done
  if [ "$gaps" -eq 0 ]; then say "no gaps remain - done"; exit 0; fi
  while pid_alive run25_gen run25_gen.sh || pid_alive claude_windows claude_windows.sh; do
    say "another run holds the repo clones; waiting"
    sleep 300
  done
  say "--- pass $pass: $gaps cell(s) missing, re-running codex batches ---"
  CYCLES="$CYCLES" BATCHES="codex_raw codex_lp" DS="$DS" CTX="$CTX" OUT="$OUT" \
    ./scripts/leobench/run25_gen.sh >> "$OUT/_genlogs/gen_codex_fill${pass}.log" 2>&1
  say "pass $pass done (exit $?)"
done
say "=== gaps after 3 passes: $(for b in codex_raw codex_lp; do missing $b; done | paste -sd+ - | bc) ==="
