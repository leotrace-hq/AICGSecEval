#!/usr/bin/env bash
# Status for a running A.S.E cohort.
#   status.sh [output_dir] [dataset]              one-shot
#   status.sh --watch [secs] [output_dir] [ds]    self-refreshing (Ctrl-C to stop)
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval

if [ "${1:-}" = "--watch" ]; then
  shift
  ivl=60
  case "${1:-}" in ''|*[!0-9]*) ;; *) ivl=$1; shift;; esac
  # macOS has no `watch`; re-exec ourselves one-shot on a timer. Ctrl-C exits.
  trap 'printf "\n"; exit 0' INT
  while :; do
    printf '\033[H\033[2J'            # home + clear, so the view does not scroll
    "$0" "$@"
    printf '\n(refreshing every %ss -- Ctrl-C to stop)\n' "$ivl"
    sleep "$ivl"
  done
fi

OUT=${1:-outputs/inscope}; DS=${2:-data/inscope_v2.json}
case "$OUT" in /*) ;; *) OUT="$ASE/$OUT";; esac
case "$DS"  in /*) ;; *) DS="$ASE/$DS";;  esac
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))))")

PIDDIR="$OUT/_genlogs"; . "$ASE/scripts/leobench/_procs.sh"
if pid_alive run25_gen run25_gen.sh; then
  echo "STATUS: generating   (started $(grep -aom1 'GEN START @ [0-9: -]*' "$OUT/_genlogs/gen.log" 2>/dev/null | sed 's/GEN START @ //'))"
else
  # "not running" alone is ambiguous: a finished run and a run that never started look the same,
  # which read as failure on 2026-09-19 when in fact every batch had completed overnight.
  _done=1
  for _b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
    _f="$OUT/generated_code/$_b/processed_instances.json"
    _n=$([ -f "$_f" ] && python3 -c "
import json;print(sum(1 for v in json.load(open('$_f')).values() if v.get('success')))" 2>/dev/null || echo 0)
    [ "${_n:-0}" -ge "$TOTAL" ] || _done=0
  done
  if [ "$_done" = 1 ]; then
    echo "STATUS: COMPLETE — all batches at $TOTAL (generation finished)"
  else
    echo "STATUS: stopped, work remaining (not currently generating)"
  fi
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
  [ "$h" -gt 0 ] && { echo "!! AUTH FAILURES in $b: $h (org policy — see LEO/ASE notes)"; fails=1; }
  # Subscription quota kills a run the same way auth does: every remaining instance fails fast
  # and the orchestrator churns on to the next batch. Do NOT grep for 'rate_limit' — the SDK
  # emits a RateLimitEvent per turn with status='allowed', so that matches hundreds of times in
  # a perfectly healthy run. Match a status that is NOT allowed, plus real exhaustion wording.
  q=$(grep -acE "RateLimitInfo\(status='(?!allowed)|overage_status='(?!allowed)|usage limit reached|too many requests" "$l" 2>/dev/null \
      || grep -acE "RateLimitInfo\(status='[a-z_]*'" "$l" | xargs -I{} sh -c 'echo 0')
  bad=$(grep -ao "RateLimitInfo(status='[a-z_]*'" "$l" | grep -vc "status='allowed'")
  ovr=$(grep -ao "overage_status='[a-z_]*'" "$l" | grep -vc "status='allowed'")
  txt=$(grep -acEi 'usage limit reached|too many requests|quota exceeded' "$l")
  tot=$((bad + ovr + txt))
  [ "$tot" -gt 0 ] && { echo "!! QUOTA signals in $b: $bad non-allowed rate-limit, $ovr overage, $txt textual"; fails=1; }
done
if [ "$fails" = 0 ]; then
  echo "auth: clean in this run's logs$([ "$stale" -gt 0 ] && echo " ($stale batch log(s) still from a previous attempt, ignored)")"
fi
exit 0
