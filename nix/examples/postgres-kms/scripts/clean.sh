#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/roles.sh
. "$SCRIPT_DIR/lib/roles.sh"

CUSTODIAN_ROLE_ARN=""
DELETE_PROVISIONING_ROLES=false
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --custodian-role-arn) CUSTODIAN_ROLE_ARN="$2"; shift ;;
    --delete-provisioning-roles) DELETE_PROVISIONING_ROLES=true ;;
    *) echo "Unknown option $1" >&2; exit 1 ;;
  esac
  shift
done

if [ ! -f "$RESOURCES_FILE" ]; then
  echo "Resources file not found: $RESOURCES_FILE"
  exit 1
fi

echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  echo "Please refresh your credentials and try again."
  echo "Resource file preserved at: $RESOURCES_FILE"
  exit 1
fi
echo "AWS credentials are valid. Proceeding with cleanup..."

AMI_ID=$(jq -r '.AMI_ID // empty' "$RESOURCES_FILE")
ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE")
INSTANCE_PROFILE_NAME=$(jq -r '.INSTANCE_PROFILE_NAME // empty' "$RESOURCES_FILE")
# Prefer the ARN. KMS_KEY_ID is the field older runs wrote, kept as a fallback so
# a resources.json from before ARN pinning still gets its key scheduled for
# deletion instead of silently orphaning it.
KMS_KEY_ARN=$(jq -r '.KMS_KEY_ARN // .KMS_KEY_ID // empty' "$RESOURCES_FILE")
INSTANCE_ID=$(jq -r '.INSTANCE_ID // empty' "$RESOURCES_FILE")
SECURITY_GROUP_ID=$(jq -r '.SECURITY_GROUP_ID // empty' "$RESOURCES_FILE")
VOLUME_ID=$(jq -r '.VOLUME_ID // empty' "$RESOURCES_FILE")
SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE")
IDENTITY_ARN=$(jq -r '.IDENTITY_ARN // empty' "$RESOURCES_FILE")

# Prefer an explicit flag; fall back to what the run recorded.
if [ -z "$CUSTODIAN_ROLE_ARN" ]; then
  CUSTODIAN_ROLE_ARN=$(jq -r '.CUSTODIAN_ROLE_ARN // empty' "$RESOURCES_FILE")
fi

CLEANUP_SUCCESS=true

run_aws_command() {
  if ! output=$(aws "$@" 2>&1); then
    echo "Error executing: aws $*"
    echo "Output: $output"
    CLEANUP_SUCCESS=false
    return 1
  fi
}

run_aws_command_optional() {
  if ! output=$(aws "$@" 2>&1); then
    echo "Warning: aws $*"
    echo "Output: $output"
    return 1
  fi
}

if [ -n "$SECRET_ARN" ]; then
  echo "Deleting Secrets Manager secret: $SECRET_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$SECRET_ARN" --force-delete-without-recovery
fi

if [ -n "$IDENTITY_ARN" ]; then
  echo "Deleting Secrets Manager secret: $IDENTITY_ARN"
  run_aws_command_optional secretsmanager delete-secret --secret-id "$IDENTITY_ARN" --force-delete-without-recovery
fi

if [ -n "$INSTANCE_ID" ]; then
  echo "Terminating EC2 instance: $INSTANCE_ID"
  run_aws_command ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  run_aws_command ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
fi

if [ -n "$SECURITY_GROUP_ID" ]; then
  echo "Deleting security group: $SECURITY_GROUP_ID"
  run_aws_command_optional ec2 delete-security-group --group-id "$SECURITY_GROUP_ID"
fi

if [ -n "$AMI_ID" ]; then
  # Snapshot IDs must be read before deregistering (describe-images fails after)
  SNAPSHOT_IDS=$(aws ec2 describe-images --image-ids "$AMI_ID" \
    --query 'Images[0].BlockDeviceMappings[*].Ebs.SnapshotId' --output text 2>/dev/null || true)

  echo "Deregistering AMI: $AMI_ID"
  run_aws_command ec2 deregister-image --image-id "$AMI_ID"

  for SNAP_ID in $SNAPSHOT_IDS; do
    if [ -n "$SNAP_ID" ] && [ "$SNAP_ID" != "None" ]; then
      echo "Deleting AMI backing snapshot: $SNAP_ID"
      run_aws_command_optional ec2 delete-snapshot --snapshot-id "$SNAP_ID"
    fi
  done
fi

if [ -n "$VOLUME_ID" ]; then
  # Wait for detach after termination; delete-volume fails with VolumeInUse otherwise
  echo "Waiting for EBS volume to become available: $VOLUME_ID"
  run_aws_command_optional ec2 wait volume-available --volume-ids "$VOLUME_ID"
  echo "Deleting EBS volume: $VOLUME_ID"
  run_aws_command ec2 delete-volume --volume-id "$VOLUME_ID"
fi

if [ -n "$INSTANCE_PROFILE_NAME" ] && [ -n "$ROLE_NAME" ]; then
  echo "Removing role from instance profile"
  run_aws_command iam remove-role-from-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" --role-name "$ROLE_NAME"

  echo "Deleting instance profile: $INSTANCE_PROFILE_NAME"
  run_aws_command iam delete-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME"

  echo "Detaching policies from IAM role: $ROLE_NAME"
  if ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); then
    for POLICY_ARN in $ATTACHED_POLICIES; do
      echo "Detaching policy: $POLICY_ARN"
      run_aws_command iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"
    done
  else
    echo "Error listing attached policies for role: $ROLE_NAME"
    CLEANUP_SUCCESS=false
  fi

  echo "Deleting inline policies from IAM role: $ROLE_NAME"
  if INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); then
    for POLICY_NAME in $INLINE_POLICIES; do
      echo "Deleting inline policy: $POLICY_NAME"
      run_aws_command iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME"
    done
  else
    echo "Error listing inline policies for role: $ROLE_NAME"
    CLEANUP_SUCCESS=false
  fi

  echo "Deleting IAM role: $ROLE_NAME"
  run_aws_command iam delete-role --role-name "$ROLE_NAME"
fi

if [ -n "$KMS_KEY_ARN" ]; then
  # Key deletion is the Custodian's, not the Operator's: the final policy grants
  # ScheduleKeyDeletion to the Custodian alone. Passthrough when no ARN is given.
  echo "Scheduling KMS key for deletion: $KMS_KEY_ARN"
  kms_err=""
  # shellcheck disable=SC2069  # 2>&1 >/dev/null is intentional: capture stderr, discard stdout
  if ! kms_err=$(assume_role_exec "$CUSTODIAN_ROLE_ARN" -- aws kms schedule-key-deletion --key-id "$KMS_KEY_ARN" --pending-window-in-days 7 2>&1 >/dev/null); then
    echo "Error executing: kms schedule-key-deletion --key-id $KMS_KEY_ARN"
    echo "Output: $kms_err"
    CLEANUP_SUCCESS=false
  fi
fi

if [ "$DELETE_PROVISIONING_ROLES" = true ]; then
  # NOTE: deleting provisioning roles requires elevated IAM permissions (iam:GetRole,
  # iam:DeleteRolePolicy, iam:DeleteRole on the NitroTpm* roles) that are NOT included
  # in the Operator role policy. Failures here mean the provisioning roles remain and
  # must be removed manually or with an appropriately privileged principal.
  for PROV_ROLE in NitroTpmCustodianRole NitroTpmProvisionerRole NitroTpmDeployerRole \
                   NitroTpmOperatorRole NitroTpmTestClientRole; do
    if aws iam get-role --role-name "$PROV_ROLE" >/dev/null 2>&1; then
      for POLICY_NAME in $(aws iam list-role-policies --role-name "$PROV_ROLE" --query 'PolicyNames[]' --output text 2>/dev/null); do
        run_aws_command_optional iam delete-role-policy --role-name "$PROV_ROLE" --policy-name "$POLICY_NAME"
      done
      echo "Deleting provisioning role: $PROV_ROLE"
      run_aws_command_optional iam delete-role --role-name "$PROV_ROLE"
    fi
  done
fi

rm -rf "$SCRIPT_DIR/../sb-keys" "$SCRIPT_DIR/../signed-image"

# Truncate rather than delete: git+file:// flake refs only see tracked paths;
# empty = unpinned. Deleting would silently orphan a future build's key lookup.
: > "$SCRIPT_DIR/../kms-key-arn.txt"


if [ "$CLEANUP_SUCCESS" = true ]; then
  echo "Cleanup completed successfully. Note that some resources may take time to be fully deleted."
  echo "Removing resource tracking files."
  rm -rf "$ARTIFACTS_DIR"
else
  echo "WARNING: Some cleanup operations failed. Resource file preserved at: $RESOURCES_FILE"
  echo "Please check your AWS credentials and re-run the cleanup script."
  echo "Failed resources may still exist and incur charges."
  exit 1
fi
