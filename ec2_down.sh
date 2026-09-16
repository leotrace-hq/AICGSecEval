#!/usr/bin/env bash
#
# ec2_down.sh — tear down the ephemeral verify host created by ec2_up.sh.
# Reads the shared state file, terminates the instance (its 500 GB root volume is deleted with
# it), then deletes the security group and key pair, and removes the local .pem. Idempotent and
# tolerant of partially-created state (a run that was interrupted mid-launch still cleans up).
set -uo pipefail

STATE_FILE="${STATE_FILE:-.ase_verify_host.json}"
[ -f "$STATE_FILE" ] || { echo "no $STATE_FILE — nothing to tear down."; exit 0; }

get() { python3 -c "import json;print(json.load(open('$STATE_FILE')).get('$1',''))"; }
REGION=$(get region); IID=$(get instance_id); SG_ID=$(get security_group_id)
KEY_NAME=$(get key_name); KEY_FILE=$(get key_file)
[ -n "$REGION" ] || { echo "state file has no region" >&2; exit 2; }

if [ -n "$IID" ]; then
  echo "[down] terminating instance $IID ..."
  aws ec2 terminate-instances --region "$REGION" --instance-ids "$IID" >/dev/null 2>&1 || true
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$IID" 2>/dev/null || true
  echo "[down] instance terminated (500GB root volume deleted with it)"
fi

if [ -n "$SG_ID" ]; then
  # the SG can only go once the instance's ENIs are released, which the wait above ensures
  if aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" 2>/dev/null; then
    echo "[down] security group $SG_ID deleted"
  else
    echo "[down] WARN could not delete security group $SG_ID (retry in a minute if the ENI is still detaching)" >&2
  fi
fi

if [ -n "$KEY_NAME" ]; then
  aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY_NAME" 2>/dev/null && echo "[down] key pair $KEY_NAME deleted" || true
fi
[ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ] && rm -f "$KEY_FILE" && echo "[down] removed local $KEY_FILE"

# only drop the state file if the instance is actually gone, so a failed teardown stays recoverable
if [ -z "$IID" ] || [ "$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
      --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)" = "terminated" ]; then
  rm -f "$STATE_FILE"
  echo "[down] done — no orphaned resources."
else
  echo "[down] instance not confirmed terminated; kept $STATE_FILE for a retry." >&2
  exit 1
fi
