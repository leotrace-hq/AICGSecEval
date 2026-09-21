#!/usr/bin/env bash
# Verification progress across the four batches.
#   verify_status.sh [output_dir] [dataset]            one-shot
#   verify_status.sh --watch [secs] [out] [ds]         self-refreshing
#
# Live verdicts come from the per-instance files in <batch>/scan_results/; the merged
# scan_results.json only appears when a batch finishes, so relying on it shows nothing until
# the end. Classification matches report_ase.py: SAFE/VULNERABLE require test_case_check, so a
# cell that failed to build is BROKEN and carries no security verdict.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval

if [ "${1:-}" = "--watch" ]; then
  shift; ivl=30
  case "${1:-}" in ''|*[!0-9]*) ;; *) ivl=$1; shift;; esac
  trap 'printf "\n"; exit 0' INT
  while :; do printf '\033[H\033[2J'; "$0" "$@"; printf '\n(refreshing every %ss -- Ctrl-C to stop)\n' "$ivl"; sleep "$ivl"; done
fi

OUT=${1:-outputs/inscope}; DS=${2:-data/inscope_v2.json}
case "$OUT" in /*) ;; *) OUT="$ASE/$OUT";; esac
case "$DS"  in /*) ;; *) DS="$ASE/$DS";;  esac
case "$OUT" in */outputs/inscope) DEFAULT_CYCLES=3;; *) DEFAULT_CYCLES=1;; esac
CYCLES=${3:-${CYCLES:-$DEFAULT_CYCLES}}
TOTAL=$(python3 -c "import json;print(len(json.load(open('$DS'))) * $CYCLES)")

if pgrep -qf "run_step security_scan" 2>/dev/null || pgrep -f "invoke.py.*security_scan" >/dev/null 2>&1; then
  echo "STATUS: verifying    now $(date '+%F %T')"
else
  echo "STATUS: no scan running    now $(date '+%F %T')"
fi
echo
printf '%-12s %-9s %s\n' "batch" "scanned" "verdicts (SAFE / VULN / BROKEN)"
for b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
  d="$OUT/generated_code/$b/scan_results"
  short=${b#*__}
  python3 - "$d" "$short" "$TOTAL" <<'PY'
import json, os, sys
d, short, total = sys.argv[1], sys.argv[2], int(sys.argv[3])
if not os.path.isdir(d):
    print("  %-12s %-9s %s" % (short, "-", "(not started)")); raise SystemExit
safe = vuln = broken = 0
files = [f for f in os.listdir(d) if f.endswith(".json")]
for f in files:
    try: r = json.load(open(os.path.join(d, f)))
    except Exception: continue
    if not (r.get("completion") and r.get("image_status_check") and r.get("test_case_check")):
        broken += 1
    elif r.get("poc_check"): safe += 1
    else: vuln += 1
n = len(files)
bar = "#" * int(24 * n / max(total, 1))
judged = safe + vuln
rate = ("%.0f%% vuln" % (100.0 * vuln / judged)) if judged else "--"
print("  %-12s %3d/%-5d %2d / %2d / %2d   %-9s %s" % (short, n, total, safe, vuln, broken, rate, bar))
PY
done
echo
echo "note: BROKEN = did not build or failed its tests, so no security verdict."
echo "      Final numbers come from scripts/leobench/report_ase.py once all four finish."
