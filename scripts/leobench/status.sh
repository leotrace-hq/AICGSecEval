#!/usr/bin/env bash
# One-shot status for a running A.S.E cohort. Usage: status.sh [output_dir] [dataset]
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
OUT=${1:-outputs/inscope}; DS=${2:-data/inscope_v2.json}
case "$OUT" in /*) ;; *) OUT="$ASE/$OUT";; esac
case "$DS"  in /*) ;; *) DS="$ASE/$DS";;  esac
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")

if pgrep -f "bash ./scripts/leobench/run25_gen.sh" >/dev/null; then
  echo "STATUS: generating   (started $(grep -aom1 'GEN START @ [0-9: -]*' "$OUT/_genlogs/gen.log" 2>/dev/null | sed 's/GEN START @ //'))"
else
  echo "STATUS: generation not running"
fi
echo "now:    $(date '+%F %T')"
echo

printf 'batch        done/%-3s  ok   bar\n' "$TOTAL"
for b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
  f="$OUT/generated_code/$b/processed_instances.json"
  short=${b#*__}
  if [ -f "$f" ]; then
    python3 -c "
import json;d=json.load(open('$f'));n=len(d);ok=sum(1 for v in d.values() if v.get('success'))
print('  %-11s %3d      %3d  %s' % ('$short', n, ok, '#'*int(28*n/max($TOTAL,1))))"
  else
    printf '  %-11s   -        -   (pending)\n' "$short"
  fi
done

echo
echo "current batch: $(grep -a '^\[gen\]' "$OUT/_genlogs/gen.log" 2>/dev/null | tail -1 | sed 's/^\[gen\] //')"
for b in claude_raw claude_lp codex_raw codex_lp; do
  l="$OUT/_genlogs/$b.log"
  [ -f "$l" ] || continue
  printf '  %-11s log touched %s\n' "$b" "$(stat -f '%Sm' -t '%H:%M:%S' "$l")"
done

echo
ev="$OUT/_server/review-events.jsonl"
if [ -f "$ev" ]; then
  python3 -c "
import json,collections
c=collections.Counter()
for l in open('$ev'):
    try: c[str(json.loads(l).get('verdict'))]+=1
    except Exception: pass
tot=sum(c.values())
print('reviews: %d total  ' % tot + '  '.join('%s=%d'%(k,v) for k,v in c.most_common()))
print('billing: ~\$%.2f  (rough, ~\$0.15/review)' % (0.15*(c.get('clean',0)+c.get('triggered',0))))"
else
  echo "reviews: none yet (raw arm fires none by design)"
fi

echo
# Only inspect logs written by the CURRENT run. A batch that has not started yet still holds
# its log from a previous attempt, and counting those reports failures that are already history.
START=$(stat -f '%m' "$OUT/_genlogs/gen.log" 2>/dev/null || echo 0)
RUNSTART=$(grep -aom1 'GEN START @ [0-9: -]*' "$OUT/_genlogs/gen.log" 2>/dev/null | sed 's/GEN START @ //')
[ -n "$RUNSTART" ] && START=$(date -j -f '%Y-%m-%d %H:%M:%S' "$RUNSTART" '+%s' 2>/dev/null || echo "$START")
fails=0; stale=0
for b in claude_raw claude_lp codex_raw codex_lp; do
  l="$OUT/_genlogs/$b.log"; [ -f "$l" ] || continue
  m=$(stat -f '%m' "$l")
  if [ "$m" -lt "$START" ]; then stale=$((stale+1)); continue; fi
  h=$(grep -acE 'oauth_org_not_allowed|organization has disabled' "$l")
  [ "$h" -gt 0 ] && { echo "!! AUTH FAILURES in $b: $h"; fails=1; }
done
if [ "$fails" = 0 ]; then
  echo "auth: clean in this run's logs$([ "$stale" -gt 0 ] && echo " ($stale batch log(s) still from a previous attempt, ignored)")"
fi
exit 0
