#!/bin/bash
# Stage 6 of 6 — PLATFORM OPERATOR.
#
# Creates the data volume, launches the instance and reports how to reach it.
#
# The Operator is blind to the data by construction: it holds no kms:Decrypt and no
# secret read, and it never sees the DEK or the certificate bundles. All it hands the
# instance is the ciphertext user-data written in stage 4. Only the instance role can
# decrypt, and only when its PCRs match.
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/aws-creds.sh
. "$SCRIPT_DIR/lib/aws-creds.sh"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

usage() {
  echo "Usage: $0 --ami-id ID --instance-profile NAME [--operator-role-arn ARN]" >&2
  echo "          [--vpc-id ID] [--debug] [--authorize-my-ip]" >&2
  echo "  --ami-id              AMI from stage 3 (required)" >&2
  echo "  --instance-profile    Instance profile from stage 1 (required)" >&2
  echo "  --operator-role-arn   Assume this role for the work (default: ambient credentials)" >&2
  echo "  --vpc-id              Target VPC (default: the account's default VPC)" >&2
  echo "  --debug               Print the SSM connection hint" >&2
  echo "  --authorize-my-ip     Allowlist this host on 5432 instead of only printing the notice" >&2
  exit 1
}

AMI_ID=""
INSTANCE_PROFILE_NAME=""
OPERATOR_ROLE_ARN=""
VPC_ID_FLAG=""
DEBUG_FLAG=""
AUTHORIZE_MY_IP=false

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --ami-id) AMI_ID="${2:?--ami-id requires a value}"; shift ;;
    --instance-profile) INSTANCE_PROFILE_NAME="${2:?--instance-profile requires a value}"; shift ;;
    --operator-role-arn) OPERATOR_ROLE_ARN="${2:?--operator-role-arn requires a value}"; shift ;;
    --vpc-id) VPC_ID_FLAG="--vpc-id ${2:?--vpc-id requires a value}"; shift ;;
    --debug) DEBUG_FLAG="--debug" ;;
    --authorize-my-ip) AUTHORIZE_MY_IP=true ;;
    *) usage ;;
  esac
  shift
done

# Individual checks so the error messages name the actual flags, not a mechanical
# transformation of the variable name (INSTANCE_PROFILE_NAME → --instance-profile,
# not --instance-profile-name).
[ -n "$AMI_ID" ] || { echo "Error: --ami-id is required." >&2; usage; }
[ -n "$INSTANCE_PROFILE_NAME" ] || { echo "Error: --instance-profile is required." >&2; usage; }

if [ ! -f "$PROJECT_DIR/artifacts/user_data.json" ]; then
  echo "Error: no artifacts/user_data.json; stage 4 must run first." >&2
  exit 1
fi

resolve_aws_credentials || exit 1

echo "Stage 6/6 (Operator): creating the encrypted data volume..." >&2
AVAILABILITY_ZONE=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- \
  aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)

if ! VOLUME_OUTPUT=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- \
      "$SCRIPT_DIR/steps/04_create_ebs_volume.sh" -z "$AVAILABILITY_ZONE"); then
  echo "Error: EBS volume creation failed." >&2
  echo "$VOLUME_OUTPUT" >&2
  exit 1
fi

VOLUME_ID=$(printf '%s' "$VOLUME_OUTPUT" | grep -oP 'Volume ID: \K.*' | head -n1)
if [ -z "$VOLUME_ID" ]; then
  echo "Error: could not extract the volume ID." >&2
  echo "$VOLUME_OUTPUT" >&2
  exit 1
fi

echo "Stage 6/6 (Operator): launching the instance..." >&2
# bash -c because assume_role_exec runs a command, not a shell function. Exporting the
# credentials into the current shell instead would leave the wrong ones active if a
# mid-stage failure skipped the restore.
if ! INSTANCE_OUTPUT=$(assume_role_exec "$OPERATOR_ROLE_ARN" -- \
      bash -c ". '$SCRIPT_DIR/lib/identity.sh'; run_instance_step '$AMI_ID' '$INSTANCE_PROFILE_NAME' '$VOLUME_ID' '$VPC_ID_FLAG' '$DEBUG_FLAG'"); then
  echo "Error: instance launch failed." >&2
  echo "$INSTANCE_OUTPUT" >&2
  exit 1
fi

INSTANCE_ID=$(printf '%s' "$INSTANCE_OUTPUT" | grep -oP 'Instance ID: \K.*' | head -n1)
PRIVATE_IP=$(printf '%s' "$INSTANCE_OUTPUT" | grep -oP 'Private IP: \K.*' | head -n1)
PUBLIC_IP=$(printf '%s' "$INSTANCE_OUTPUT" | grep -oP 'Public IP: \K.*' | head -n1)
SG_ID=$(printf '%s' "$INSTANCE_OUTPUT" | grep -oP 'Security Group ID: \K.*' | head -n1)

if [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] || [ -z "$SG_ID" ]; then
  echo "Error: could not extract the instance details." >&2
  echo "$INSTANCE_OUTPUT" >&2
  exit 1
fi

echo "VOLUME_ID: $VOLUME_ID"
echo "INSTANCE_ID: $INSTANCE_ID"
echo "PRIVATE_IP: $PRIVATE_IP"
echo "PUBLIC_IP: $PUBLIC_IP"
echo "SECURITY_GROUP_ID: $SG_ID"

# Ported from the former postgres-kms start.sh (deleted in the six-stage refactor):
# without this an operator has no idea how to reach the database that was just launched.
{
  echo ""
  echo "=== Deployment summary ==="
  echo "  AMI ID:            $AMI_ID"
  echo "  Instance Profile:  $INSTANCE_PROFILE_NAME"
  echo "  EBS Volume ID:     $VOLUME_ID"
  echo "  EC2 Instance ID:   $INSTANCE_ID"
  echo "  EC2 Private IP:    $PRIVATE_IP"
  echo "  EC2 Public IP:     $PUBLIC_IP"
  echo "  Security Group ID: $SG_ID"
  echo "  Artifacts:         $PROJECT_DIR/artifacts/"
} >&2

if [ "$AUTHORIZE_MY_IP" = true ]; then
  assume_role_exec "$OPERATOR_ROLE_ARN" -- \
    bash -c ". '$SCRIPT_DIR/lib/identity.sh'; authorize_my_ip '$SG_ID'" >&2 || exit 1
else
  print_sg_authorization_notice "$SG_ID" >&2
fi

echo "Once your host is allowlisted, connect over mTLS to: $PUBLIC_IP:5432" >&2
if [ -n "$DEBUG_FLAG" ]; then
  echo "Debug build: aws ssm start-session --region ${AWS_DEFAULT_REGION} --target $INSTANCE_ID" >&2
fi
