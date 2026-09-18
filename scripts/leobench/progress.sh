#!/usr/bin/env bash
# Per-batch generation progress. Usage: progress.sh [output_dir] [dataset]
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
OUT=${1:-$ASE/outputs/stage3}
DS=${2:-$ASE/data/run25_v2.json}
case "$OUT" in /*) ;; *) OUT="$ASE/$OUT";; esac
case "$DS"  in /*) ;; *) DS="$ASE/$DS";; esac
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")
echo "cohort $(basename "$DS") — $TOTAL instances"
for b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
  f="$OUT/generated_code/$b/processed_instances.json"
  if [ -f "$f" ]; then
    python3 -c "
import json;d=json.load(open('$f'))
ok=sum(1 for v in d.values() if v.get('success'))
n=len(d); print('  %-26s %3d/%s done, %3d ok  %s' % ('$b', n, '$TOTAL', ok, '#'*int(30*n/max($TOTAL,1))))"
  else
    printf '  %-26s not started\n' "$b"
  fi
done
