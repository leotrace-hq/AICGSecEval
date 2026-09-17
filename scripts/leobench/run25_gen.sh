#!/usr/bin/env bash
# Generate the 25-instance A.S.E arm locally: both agents x both arms, 1 cycle.
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

DS=data/run25_v2.json
CTX=data/run25_context.json
OUT=outputs/stage3
PY=.venv/bin/python
LOGDIR="$OUT/_genlogs"; mkdir -p "$LOGDIR"

run() {  # $1=agent_name  $2=arm  $3=batch_id
  local agent="$1" arm="$2" batch="$3"
  local mflag=()
  [ "$agent" = claude_code ] && mflag=(--claude_model claude-sonnet-4-5)  # 4.5 dodges Sonnet-5 cyber safeguards; codex: default
  echo "=========================================================="
  echo "[gen] $agent / $arm -> batch=$batch  @ $(date '+%F %T')"
  echo "=========================================================="
  "$PY" invoke.py --run_step gen_code \
      --agent --agent_name "$agent" --arm "$arm" "${mflag[@]}" \
      --batch_id "$batch" --dataset_path "$DS" --retrieval_data_path "$CTX" \
      --num_cycles 1 --output_dir "$OUT" \
      2>&1 | sed -E 's/gh[pousr]_[A-Za-z0-9]{16,}/<REDACTED-GH-TOKEN>/g' | tee "$LOGDIR/${batch}.log"
  echo "[gen] $batch finished @ $(date '+%F %T')"
}

echo "### RUN25 GEN START @ $(date '+%F %T') — 4 batches, sequential ###"
run claude_code raw        claude_raw
run claude_code leoprevent claude_lp
run codex       raw        codex_raw
run codex       leoprevent codex_lp
echo "### RUN25 GEN DONE @ $(date '+%F %T') ###"
echo "generated_code dirs:"; ls -d "$OUT"/generated_code/*/ 2>/dev/null
