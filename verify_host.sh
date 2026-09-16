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
#                    [--workers 20] [--remote-repo '~/ase'] [--ssh-opts '-i key.pem']
#
# Runs the two arms one --batch at a time; call it once per batch (e.g. claude_lp then claude_raw).
set -euo pipefail

HOST="" AGENT="" BATCH="" DATASET="data/data_v2.json" OUTDIR="outputs" WORKERS=16
REMOTE_REPO='~/ase' SSH_OPTS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --host)        HOST="$2"; shift 2;;
    --agent)       AGENT="$2"; shift 2;;
    --batch)       BATCH="$2"; shift 2;;
    --dataset)     DATASET="$2"; shift 2;;
    --output-dir)  OUTDIR="$2"; shift 2;;
    --workers)     WORKERS="$2"; shift 2;;
    --remote-repo) REMOTE_REPO="$2"; shift 2;;
    --ssh-opts)    SSH_OPTS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] && [ -n "$AGENT" ] && [ -n "$BATCH" ] || {
  echo "required: --host, --agent, --batch (see header for usage)" >&2; exit 2; }

GEN_DIR="$OUTDIR/generated_code/${AGENT}__${BATCH}"
[ -d "$GEN_DIR" ] || { echo "no local generated code at $GEN_DIR — run gen_code first" >&2; exit 1; }

SSH() { ssh $SSH_OPTS "$HOST" "$@"; }
RSYNC() { rsync -az -e "ssh $SSH_OPTS" "$@"; }
# expand ~ on the remote side once, so rsync/ssh paths agree
RROOT="$(SSH "eval echo $REMOTE_REPO")"

echo "[verify] ship generated code + dataset to $HOST:$RROOT"
SSH "mkdir -p '$RROOT/$OUTDIR/generated_code' '$RROOT/$(dirname "$DATASET")'"
RSYNC --delete "$GEN_DIR/" "$HOST:$RROOT/$GEN_DIR/"
RSYNC "$DATASET" "$HOST:$RROOT/$DATASET"

echo "[verify] run security_scan on the host ($WORKERS workers, native amd64)"
# --run_step security_scan does NOT touch the agents; the --agent/--agent_name pair is only there
# to satisfy invoke.py's argument parser, and --github_token is unused by the scan.
SSH "cd '$RROOT' && .venv/bin/python invoke.py \
      --run_step security_scan --agent --agent_name '$AGENT' \
      --batch_id '$BATCH' --dataset_path '$DATASET' \
      --output_dir '$OUTDIR' --max_workers '$WORKERS' --github_token unused"

echo "[verify] fetch verdicts back"
RSYNC "$HOST:$RROOT/$GEN_DIR/scan_results.json" "$GEN_DIR/scan_results.json"
RSYNC "$HOST:$RROOT/$GEN_DIR/"'*_eval_results.json' "$GEN_DIR/" 2>/dev/null || true

echo "[verify] done — verdicts in $GEN_DIR/scan_results.json"
