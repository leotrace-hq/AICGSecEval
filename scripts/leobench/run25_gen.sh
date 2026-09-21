#!/usr/bin/env bash
# Generate an A.S.E cohort locally: both agents x both arms, 1 cycle.
# Cohort is selectable so run25 and the in-scope cohort share one orchestrator:
#   DS/CTX/OUT override the dataset, its context and the output dir (defaults = run25).
# Batches run SEQUENTIALLY — they share per-instance repo clones, so concurrent batches race
# on os.makedirs(raw_repo_dir) (invoke.py). Only the leoprevent batches bill (LeoPrevent /review).
# Verification is a SEPARATE step on the amd64 EC2 host (verify_host.sh); this only gen_codes.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
LP=/Users/bbaukema/Documents/github/leotrace-hq/leoprevent
cd "$ASE"

export LEOPREVENT_ENV_FILE="$LP/server/.env"          # supplies CLAUDE_CODE_OAUTH_TOKEN (leoprevent arm)
export LEOPREVENT_PLUGIN_DIR="$LP/plugin"             # required for --arm leoprevent
export LEOPREVENT_SERVER_URL=http://127.0.0.1:8787
# Abort a git clone that stalls (e.g. network dropped by a sleep) instead of hanging forever;
# A.S.E records the failure, moves on, and a later resume retries it.
export GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=60

# The token goes in the ENVIRONMENT, never on the command line: an argv token is world-readable
# via `ps` for as long as the run lasts, and is captured verbatim into the tee'd log below.
# invoke.py defaults --github_token to $GITHUB_TOKEN.
export GITHUB_TOKEN; GITHUB_TOKEN=$(gh auth token)

DS=${DS:-data/run25_v2.json}
CTX=${CTX:-data/run25_context.json}
OUT=${OUT:-outputs/stage3}
# A.S.E keys completions as <instance>_cycleN and skips keys already recorded, so raising
# CYCLES adds the new cycles and reuses the ones already generated.
CYCLES=${CYCLES:-1}
AUTH=${AUTH:-subscription}
CLAUDE_MODEL=${CLAUDE_MODEL:-claude-sonnet-4-5}
echo "### cohort: $DS ($(python3 -c "import json;print(len(json.load(open('$DS'))))") instances) -> $OUT ###"
PY=.venv/bin/python
LOGDIR="$OUT/_genlogs"; mkdir -p "$LOGDIR"
PIDDIR="$LOGDIR"; . scripts/leobench/_procs.sh
pid_write run25_gen

# A batch that produced ZERO successful generations is never a normal outcome -- it means
# something systemic (expired token, org policy change, exhausted subscription quota, dead
# network). On 2026-09-18 an org-policy change failed all 67 instances in 18 minutes and the
# orchestrator then churned on through the remaining three batches for nothing. Stop instead,
# so a human looks at it while the run is still cheap to restart.
#
# Deliberately NOT a consecutive-failure heuristic: individual instances fail for legitimate
# reasons all the time (a dead upstream repo, an agent that gives up), and a threshold on those
# would eventually kill a good run. Zero-of-everything is unambiguous.
#
# Resume-safe: A.S.E counts already-completed instances from a previous run in this file, so a
# batch that is fully done and skips every instance still reports its successes, not zero.
batch_successes() {  # $1=agent  $2=batch -> prints the success count (0 if no record at all)
  local f="$OUT/generated_code/$1__$2/processed_instances.json"
  [ -f "$f" ] || { echo 0; return; }
  python3 -c "
import json
try: d = json.load(open('$f'))
except Exception: print(0); raise SystemExit
print(sum(1 for v in d.values() if v.get('success')))
" 2>/dev/null || echo 0
}

run() {  # $1=agent_name  $2=arm  $3=batch_id
  local agent="$1" arm="$2" batch="$3"
  local mflag=()
  [ "$agent" = claude_code ] && mflag=(--claude_model "$CLAUDE_MODEL" --auth "$AUTH")  # codex: default
  echo "=========================================================="
  echo "[gen] $agent / $arm -> batch=$batch  @ $(date '+%F %T')"
  echo "=========================================================="
  "$PY" invoke.py --run_step gen_code \
      --agent --agent_name "$agent" --arm "$arm" "${mflag[@]}" \
      --batch_id "$batch" --dataset_path "$DS" --retrieval_data_path "$CTX" \
      --num_cycles "$CYCLES" --output_dir "$OUT" \
      2>&1 | sed -E 's/gh[pousr]_[A-Za-z0-9]{16,}/<REDACTED-GH-TOKEN>/g' | tee "$LOGDIR/${batch}.log"
  echo "[gen] $batch finished @ $(date '+%F %T')"

  local ok; ok=$(batch_successes "$agent" "$batch")
  if [ "${ok:-0}" -eq 0 ]; then
    echo "##############################################################"
    echo "### ABORT: $batch produced 0 successful generations."
    echo "### Something systemic is wrong -- check auth, quota and network:"
    echo "###   $LOGDIR/${batch}.log"
    echo "### Remaining batches SKIPPED. Nothing is recorded as failed, so"
    echo "### re-running this script after the fix resumes where it stopped."
    echo "##############################################################"
    exit 1
  fi
  echo "[gen] $batch: $ok successful generation(s) recorded"
}

# BATCHES selects which of the four to run, space-separated; default all. The Claude and Codex
# arms authenticate independently (Claude subscription vs ChatGPT), so when one provider's quota
# is exhausted the other's batches can still make progress -- run them rather than idle.
BATCHES=${BATCHES:-"claude_raw claude_lp codex_raw codex_lp"}
echo "### RUN25 GEN START @ $(date '+%F %T') — batches: $BATCHES ###"
for b in $BATCHES; do
  case "$b" in
    claude_raw) run claude_code raw        claude_raw ;;
    claude_lp)  run claude_code leoprevent claude_lp  ;;
    codex_raw)  run codex       raw        codex_raw  ;;
    codex_lp)   run codex       leoprevent codex_lp   ;;
    *) echo "unknown batch '$b' (want: claude_raw claude_lp codex_raw codex_lp)" >&2; exit 2 ;;
  esac
done
echo "### RUN25 GEN DONE @ $(date '+%F %T') ###"
echo "generated_code dirs:"; ls -d "$OUT"/generated_code/*/ 2>/dev/null
