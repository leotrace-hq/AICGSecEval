#!/usr/bin/env bash
#
# ec2_up.sh — create an EPHEMERAL amd64 Spot host to verify A.S.E on, provisioned to run
# `verify_host.sh`'s security_scan natively (no QEMU). Pairs with ec2_down.sh, which tears
# down everything this creates. State is written to a JSON file both scripts share, so a
# teardown works even if this script is interrupted mid-launch.
#
# Creates: one key pair (private key saved locally, chmod 600), one security group (inbound
# SSH from YOUR public IP /32 only, egress all for Docker Hub), one Spot m7i.8xlarge with a
# 500 GB gp3 root volume (DeleteOnTermination). user-data installs Docker + Python, clones the
# fork, and builds the scan venv. Verification is LLM-free, so the host gets NO credentials.
#
# Usage:   ./ec2_up.sh            # then wait for provisioning, run verify_host.sh, then ec2_down.sh
# Override via env: REGION, INSTANCE_TYPE, VOLUME_GB, REPO_URL, REPO_BRANCH.
set -euo pipefail

REGION="${REGION:-$(aws configure get region 2>/dev/null || true)}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m7i.8xlarge}"
VOLUME_GB="${VOLUME_GB:-500}"
TAG="${TAG:-ase-verify}"
STATE_FILE="${STATE_FILE:-.ase_verify_host.json}"
REPO_URL="${REPO_URL:-https://github.com/leotrace-hq/AICGSecEval.git}"
REPO_BRANCH="${REPO_BRANCH:-leobench-arm}"
ON_DEMAND="${ON_DEMAND:-0}"   # default: try Spot, fall back to on-demand. --on-demand forces on-demand.
for a in "$@"; do case "$a" in --on-demand) ON_DEMAND=1;; *) echo "unknown arg: $a" >&2; exit 2;; esac; done

[ -n "$REGION" ] || { echo "no AWS region — set REGION or run 'aws configure'" >&2; exit 2; }
[ -e "$STATE_FILE" ] && { echo "$STATE_FILE exists — a host may already be up. Run ./ec2_down.sh first." >&2; exit 1; }

write_state() {  # write whatever is known so far, so ec2_down.sh can always clean up
  printf '{"region":"%s","key_name":"%s","key_file":"%s","security_group_id":"%s","instance_id":"%s"}\n' \
    "$REGION" "${KEY_NAME:-}" "${KEY_FILE:-}" "${SG_ID:-}" "${IID:-}" > "$STATE_FILE"
}

echo "[up] region=$REGION type=$INSTANCE_TYPE volume=${VOLUME_GB}GB market=$([ "$ON_DEMAND" = 1 ] && echo on-demand || echo 'spot (on-demand fallback)')"

AMI=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text)
echo "[up] ami=$AMI (AL2023 x86_64)"

MYIP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
[[ "$MYIP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "couldn't detect public IP" >&2; exit 1; }
echo "[up] SSH will be open to ${MYIP}/32 only (never 0.0.0.0/0)"

SUFFIX=$(date +%Y%m%d-%H%M%S)
KEY_NAME="${TAG}-${SUFFIX}"; KEY_FILE="${KEY_NAME}.pem"; SG_NAME="${TAG}-${SUFFIX}"
SG_ID="" IID=""

aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
  --query 'KeyMaterial' --output text > "$KEY_FILE"
chmod 600 "$KEY_FILE"; write_state
echo "[up] key pair $KEY_NAME -> $KEY_FILE"

VPC=$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
[ "$VPC" != "None" ] || { echo "no default VPC in $REGION" >&2; exit 1; }
SG_ID=$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" \
  --description "A.S.E ephemeral verify host (SSH)" --vpc-id "$VPC" --query 'GroupId' --output text)
write_state
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "${MYIP}/32" >/dev/null
echo "[up] security group $SG_ID (ssh 22 <- ${MYIP}/32, egress all)"

USERDATA=$(cat <<EOF
#!/bin/bash
set -e
dnf install -y docker git python3.11 python3.11-pip
systemctl enable --now docker
usermod -aG docker ec2-user
sudo -u ec2-user bash -lc '
  cd ~ && git clone -b ${REPO_BRANCH} ${REPO_URL} ase && cd ase
  python3.11 -m venv .venv && .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q docker gitpython tqdm requests chardet numpy tenacity openai transformers claude-agent-sdk filelock
'
touch /home/ec2-user/PROVISIONED
EOF
)

BDM="[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"VolumeSize\":${VOLUME_GB},\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]"

_run() {  # run-instances with any extra flags passed as "$@" (the market option, or none)
  aws ec2 run-instances --region "$REGION" \
    --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" "$@" \
    --block-device-mappings "$BDM" --user-data "$USERDATA" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${TAG}}]" \
    --query 'Instances[0].InstanceId' --output text
}

_wait_healthy() {  # poll $IID: 0 once it reaches running + status-ok, 1 if terminated or timed out.
  local i state ok                # catches Spot that reaches 'running' then gets reclaimed (~2 min).
  for i in $(seq 1 42); do        # ~7 min; instance status checks take a few minutes to pass
    state=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo unknown)
    case "$state" in
      terminated|shutting-down) return 1;;
      running)
        ok=$(aws ec2 describe-instance-status --region "$REGION" --instance-ids "$IID" \
             --query 'InstanceStatuses[0].InstanceStatus.Status' --output text 2>/dev/null || echo initializing)
        [ "$ok" = ok ] && return 0;;
    esac
    sleep 10
  done
  return 1
}

launch_with() {  # $1 = spot|ondemand ; sets IID, returns 0 only if the instance comes up healthy
  if [ "$1" = spot ]; then IID=$(_run --instance-market-options 'MarketType=spot' 2>/dev/null) || return 1
  else                     IID=$(_run 2>/dev/null) || return 1; fi
  write_state
  echo "[up] launched $1 instance $IID — waiting for it to come up healthy ..."
  _wait_healthy
}

if [ "$ON_DEMAND" = 1 ]; then
  launch_with ondemand || { echo "[up] on-demand launch failed" >&2; exit 1; }
elif launch_with spot; then
  echo "[up] Spot instance is healthy"
else
  echo "[up] Spot unavailable (no capacity / reclaimed) — falling back to on-demand ..."
  [ -n "${IID:-}" ] && aws ec2 terminate-instances --region "$REGION" --instance-ids "$IID" >/dev/null 2>&1 || true
  IID=""; write_state
  launch_with ondemand || { echo "[up] on-demand launch also failed" >&2; exit 1; }
  echo "[up] on-demand instance is healthy"
fi

IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "[up] running at $IP"
echo
echo "  Provisioning (Docker + venv + clone) runs via user-data; wait for it:"
echo "    ssh -i $KEY_FILE ec2-user@$IP 'while [ ! -f PROVISIONED ]; do sleep 5; done; echo ready'"
echo
echo "  Then verify a batch (image pull happens on first scan):"
echo "    ./verify_host.sh --host ec2-user@$IP --agent claude_code --batch claude_lp \\"
echo "        --dataset data/pilot_v2.json --workers 20 --ssh-opts '-i $KEY_FILE'"
echo
echo "  When done:  ./ec2_down.sh    # terminates + deletes instance, 500GB volume, SG, key"
