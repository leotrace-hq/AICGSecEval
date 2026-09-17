#!/usr/bin/env bash
# run25 generation progress: per-batch counts from each batch's processed_instances.json.
set -uo pipefail
OUT=${1:-/Users/bbaukema/Documents/github/Tencent/AICGSecEval/outputs/stage3}
TOTAL=$(python3 -c "import json;print(len(json.load(open('/Users/bbaukema/Documents/github/Tencent/AICGSecEval/data/run25_v2.json'))))")
printf '%-28s %s\n' "batch" "done/ok  (of $TOTAL)"
for b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
  f="$OUT/generated_code/$b/processed_instances.json"
  if [ -f "$f" ]; then
    python3 -c "
import json;d=json.load(open('$f'))
ok=sum(1 for v in d.values() if v.get('success'))
print('%-28s %d done, %d ok' % ('$b', len(d), ok))"
  else
    printf '%-28s not started\n' "$b"
  fi
done
