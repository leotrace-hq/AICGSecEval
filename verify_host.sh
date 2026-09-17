#!/usr/bin/env bash
#
# verify_host.sh — run A.S.E's security_scan on a remote amd64 host.
#
# LeoBench generates code locally (agents on subscriptions, LeoPrevent review against a local
# server) and verifies remotely: the amd64 Docker images run NATIVELY on an x86_64 host instead
# of under QEMU emulation on an arm64 Mac, which is both faster and faithful for the C
# memory-corruption PoCs. A.S.E already splits `--run_step gen_code` from `security_scan`; this
# script is the seam — it ships the locally-generated code up, verifies there, and fetches the
# verdicts back.
#
# The verify host needs NO LeoPrevent server, NO API keys, NO credentials — verification is
# pure Docker (build/test/poc), LLM-free. It only needs: this repo checked out, its .venv with
# the scan deps, Docker running, and outbound network to pull the task images.
#
# ── Provision the host once (x86_64, e.g. m7i.8xlarge, see ASE-INTEGRATION.md) ──
#   sudo dnf -y install docker git python3.11 && sudo systemctl enable --now docker
#   git clone <this-fork> ase && cd ase
#   python3.11 -m venv .venv
#   .venv/bin/pip install docker gitpython tqdm requests chardet   # scan-only deps (no agent/SDK)
#   # images are pulled lazily by the scan; pre-pull with data/*.json image fields to warm the cache
#
# ── Usage ──
#   ./verify_host.sh --host user@1.2.3.4 --agent claude_code --batch claude_lp \
#                    --dataset data/pilot_v2.json [--output-dir outputs/pilot] \
#                    [--workers 20] [--remote-repo ase] [--ssh-opts '-i key.pem']
#   (--remote-repo is relative to the remote $HOME, or an absolute path; letters/digits/_./- only)
#
# Runs the two arms one --batch at a time; call it once per batch (e.g. claude_lp then claude_raw).
set -euo pipefail

HOST="" AGENT="" BATCH="" DATASET="data/data_v2.json" OUTDIR="outputs" WORKERS=16
REMOTE_REPO='ase' SSH_OPTS="" NUM_CYCLES=1   # NUM_CYCLES MUST match what gen_code produced
                                              # (REMOTE_REPO: relative to remote $HOME, or absolute)

while [ $# -gt 0 ]; do
  case "$1" in
    --host)        HOST="$2"; shift 2;;
    --agent)       AGENT="$2"; shift 2;;
    --batch)       BATCH="$2"; shift 2;;
    --dataset)     DATASET="$2"; shift 2;;
    --output-dir)  OUTDIR="$2"; shift 2;;
    --workers)     WORKERS="$2"; shift 2;;
    --num-cycles)  NUM_CYCLES="$2"; shift 2;;
    --remote-repo) REMOTE_REPO="$2"; shift 2;;
    --ssh-opts)    SSH_OPTS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] && [ -n "$AGENT" ] && [ -n "$BATCH" ] || {
  echo "required: --host, --agent, --batch (see header for usage)" >&2; exit 2; }

# Every value below is interpolated into a remote shell command over SSH, so validate each
# against a strict allowlist first — no shell metacharacter can reach the remote shell.
_ck() { [[ "$2" =~ $3 ]] || { echo "invalid --$1: '$2' must match $3" >&2; exit 2; }; }
_ck host        "$HOST"        '^[A-Za-z0-9._@:-]+$'
_ck agent       "$AGENT"       '^[A-Za-z0-9_-]+$'
_ck batch       "$BATCH"       '^[A-Za-z0-9_-]+$'
_ck dataset     "$DATASET"     '^[A-Za-z0-9_./-]+$'
_ck output-dir  "$OUTDIR"      '^[A-Za-z0-9_./-]+$'
_ck workers     "$WORKERS"     '^[0-9]+$'
_ck num-cycles  "$NUM_CYCLES"  '^[0-9]+$'
_ck remote-repo "$REMOTE_REPO" '^[A-Za-z0-9_./-]+$'   # relative-to-$HOME or absolute; no ~, no metacharacters

GEN_DIR="$OUTDIR/generated_code/${AGENT}__${BATCH}"
[ -d "$GEN_DIR" ] || { echo "no local generated code at $GEN_DIR — run gen_code first" >&2; exit 1; }

SSH() { ssh $SSH_OPTS "$HOST" "$@"; }
RSYNC() { rsync -az -e "ssh $SSH_OPTS" "$@"; }
# Resolve the remote root WITHOUT eval. An absolute --remote-repo is used as-is; otherwise it is
# taken relative to the remote account's own $HOME, expanded remote-side (never from a CLI value).
if [[ "$REMOTE_REPO" == /* ]]; then
  RROOT="$REMOTE_REPO"
else
  RROOT="$(SSH 'printf %s "$HOME"')/$REMOTE_REPO"
fi

echo "[verify] ship generated code + dataset to $HOST:$RROOT"
SSH "mkdir -p '$RROOT/$OUTDIR/generated_code' '$RROOT/$(dirname "$DATASET")'"
# Ship the generated source (the <instance>_cycleN dirs) AND processed_instances.json — the latter
# is a gen OUTPUT that the scan reads as its INPUT (get_success_folders: the list of folders to
# scan). But a prior run's scan VERDICTS (scan_results.json/scan_results/, *_eval_results.json,
# *_metrics.json) must NOT go up: the scan's resume filter skips any instance already in
# scan_results/, so shipping them makes the host re-report the OLD (e.g. QEMU) result instead of
# scanning natively. --delete keeps the remote tree in sync.
RSYNC --delete \
  --exclude 'scan_results.json' --exclude 'scan_results/' \
  --exclude '*_eval_results.json' --exclude '*_metrics.json' \
  "$GEN_DIR/" "$HOST:$RROOT/$GEN_DIR/"
RSYNC "$DATASET" "$HOST:$RROOT/$DATASET"
# Belt and suspenders on a reused host: drop only stale verdicts (never processed_instances.json)
# so the scan re-runs from scratch.
SSH "cd '$RROOT/$GEN_DIR' && rm -rf scan_results scan_results.json ./*_eval_results.json ./*_metrics.json"

echo "[verify] run security_scan on the host ($WORKERS workers, $NUM_CYCLES cycle(s), native amd64)"
# --run_step security_scan does NOT touch the agents; the --agent/--agent_name pair is only there
# to satisfy invoke.py's argument parser, and --github_token is unused by the scan.
# --num_cycles MUST match what gen_code produced, or evaluate_stability_score KeyErrors on the
# empty cycle_results for cycles that were never generated (A.S.E run_evaluate.py:400).
# NOTE the `|| scan_rc=$?`: A.S.E calls exit(-1) when any instance still fails after 3 retries
# (run_security_scan.py:388), which a permanently-unpullable task image guarantees forever. Its
# `finally: merge_scan_results(...)` still writes scan_results.json for everything that DID scan,
# so a non-zero exit must NOT abort us under `set -e` before the fetch below — otherwise a couple
# of dead upstream images silently throw away a whole batch of good verdicts.
scan_rc=0
SSH "cd '$RROOT' && .venv/bin/python invoke.py \
      --run_step security_scan --agent --agent_name '$AGENT' \
      --batch_id '$BATCH' --dataset_path '$DATASET' --num_cycles '$NUM_CYCLES' \
      --output_dir '$OUTDIR' --max_workers '$WORKERS' --github_token unused" || scan_rc=$?
[ "$scan_rc" -ne 0 ] && echo "[verify] scan exited $scan_rc — fetching partial verdicts anyway" >&2

echo "[verify] fetch verdicts back"
RSYNC "$HOST:$RROOT/$GEN_DIR/scan_results.json" "$GEN_DIR/scan_results.json"
RSYNC "$HOST:$RROOT/$GEN_DIR/"'*_eval_results.json' "$GEN_DIR/" 2>/dev/null || true

if [ "$scan_rc" -ne 0 ]; then
  echo "[verify] done (scan reported failures, rc=$scan_rc) — verdicts in $GEN_DIR/scan_results.json" >&2
  echo "[verify] instances that never scanned are absent from it; the report treats them as BROKEN" >&2
else
  echo "[verify] done — verdicts in $GEN_DIR/scan_results.json"
fi
