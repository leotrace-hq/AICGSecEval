#!/usr/bin/env bash
# Verify all four stage3 batches on ONE ephemeral amd64 EC2 host, then ALWAYS tear down.
# Teardown is guaranteed by `trap cleanup EXIT` AND an independent AWS sweep that fails loudly
# if anything is still alive. Run only AFTER run25_gen.sh has finished.
set -uo pipefail
ASE=/Users/bbaukema/Documents/github/Tencent/AICGSecEval
cd "$ASE"
REGION=$(aws configure get region)
OUT=outputs/stage3
DS=data/run25_v2.json
TAG=ase-verify

# On-demand by DEFAULT, not Spot. This job is ~20 minutes end to end, so the Spot discount saves
# roughly a dollar — while a mid-run reclamation costs the whole run. That is not hypothetical:
# on 2026-09-17 AWS reclaimed the host 7 minutes in (Server.SpotInstanceTermination, "no Spot
# capacity available"), killing all four batches. ec2_up.sh's Spot->on-demand fallback does NOT
# cover this: it only retries a failed LAUNCH, and cannot protect an instance already running.
# Opt back into Spot with ON_DEMAND=0 for long or genuinely restartable jobs.
: "${ON_DEMAND:=1}"; export ON_DEMAND

sweep() {  # independent check: 0 if truly nothing left, 1 if any resource remains
  local left=0
  [ -e .ase_verify_host.json ] && { echo "[sweep] STATE FILE STILL PRESENT"; left=1; }
  local ins; ins=$(aws ec2 describe-instances --region "$REGION" \
    --filters Name=tag:Name,Values=$TAG Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)
  [ -n "$ins" ] && { echo "[sweep] LEFTOVER INSTANCE(S): $ins"; left=1; }
  local sg; sg=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters Name=group-name,Values="${TAG}-*" --query 'SecurityGroups[].GroupId' --output text 2>/dev/null)
  [ -n "$sg" ] && { echo "[sweep] LEFTOVER SG(S): $sg"; left=1; }
  local kp; kp=$(aws ec2 describe-key-pairs --region "$REGION" \
    --filters Name=key-name,Values="${TAG}-*" --query 'KeyPairs[].KeyName' --output text 2>/dev/null)
  [ -n "$kp" ] && { echo "[sweep] LEFTOVER KEY PAIR(S): $kp"; left=1; }
  ls "$ASE"/${TAG}-*.pem >/dev/null 2>&1 && { echo "[sweep] LEFTOVER LOCAL .pem"; left=1; }
  return $left
}

cleanup() {
  echo "[v4] === TEARDOWN @ $(date '+%T') ==="
  ./ec2_down.sh 2>&1 | sed 's/^/[down] /'
  # ec2_down is idempotent; if state remains, retry once after a pause for ENI detach
  if [ -e .ase_verify_host.json ]; then echo "[v4] state remained, retrying teardown in 30s"; sleep 30; ./ec2_down.sh 2>&1 | sed 's/^/[down2] /'; fi
  echo "[v4] === POST-TEARDOWN SWEEP ==="
  if sweep; then echo "[v4] CLEAN — no AWS resources remain, nothing billing."; else
    echo "[v4] !!! RESOURCES REMAIN — MANUAL CHECK NEEDED (region $REGION, tag $TAG) !!!"; fi
}
trap cleanup EXIT

echo "[v4] === LAUNCH @ $(date '+%T') === (market=$([ "$ON_DEMAND" = 1 ] && echo on-demand || echo spot))"
./ec2_up.sh 2>&1 | sed 's/^/[up] /' || { echo "[v4] launch failed"; exit 1; }
IID=$(python3 -c "import json;print(json.load(open('.ase_verify_host.json'))['instance_id'])")
KEY=$(python3 -c "import json;print(json.load(open('.ase_verify_host.json'))['key_file'])")
IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
      --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
SOPTS="-i $KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
echo "[v4] host $IID at $IP"

echo "[v4] === WAIT FOR PROVISIONING ==="
ready=0
for i in $(seq 1 90); do
  if ssh $SOPTS ec2-user@"$IP" 'test -f PROVISIONED' 2>/dev/null; then ready=1; echo "[v4] provisioned after ~$((i*10))s"; break; fi
  sleep 10
done
[ "$ready" = 1 ] || { echo "[v4] provisioning timed out"; exit 1; }

# batch -> agent map
verify_batch() {  # $1=agent_name  $2=batch
  local agent="$1" batch="$2" gd="$OUT/generated_code/${1}__${2}"
  if [ ! -d "$gd" ]; then echo "[v4] SKIP $batch — no local generated code ($gd)"; return; fi
  local nok; nok=$(python3 -c "import json;d=json.load(open('$gd/processed_instances.json'));print(sum(1 for v in d.values() if v.get('success')))" 2>/dev/null || echo 0)
  if [ "${nok:-0}" -eq 0 ]; then echo "[v4] SKIP $batch — 0 successful generations"; return; fi
  echo "[v4] === VERIFY $batch ($nok generated) @ $(date '+%T') ==="
  ./verify_host.sh --host ec2-user@"$IP" --agent "$agent" --batch "$batch" \
    --dataset "$DS" --output-dir "$OUT" --workers 20 --num-cycles 1 \
    --ssh-opts "$SOPTS" 2>&1 | sed "s/^/[$batch] /"
}

verify_batch claude_code claude_raw
verify_batch claude_code claude_lp
verify_batch codex       codex_raw
verify_batch codex       codex_lp

echo "[v4] === VERDICTS ==="
for b in claude_code__claude_raw claude_code__claude_lp codex__codex_raw codex__codex_lp; do
  f="$OUT/generated_code/$b/scan_results.json"
  echo "--- $b ---"; [ -f "$f" ] && python3 -c "import json;d=json.load(open('$f'));print(' safe(poc_check=T):',sum(1 for x in d if x.get('poc_check')),'/',len(d))" 2>/dev/null || echo "  (no scan_results.json)"
done
echo "[v4] === done (teardown runs next) @ $(date '+%T') ==="
