#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
ARTIFACTS_DIR="$SCRIPT_DIR/../artifacts"
RESOURCES_FILE="$ARTIFACTS_DIR/resources.json"

# shellcheck source=lib/identity.sh
. "$SCRIPT_DIR/lib/identity.sh"

SECURE_BOOT_FLAG=""
DEBUG_FLAG=""
TIMEOUT=600
NO_CLEANUP=false
SKIP_SG_UPDATE=false
AUTHORIZE_MY_IP=false
ADMIN_ROLE_ARN_OVERRIDE=""
VPC_ID_FLAG=""
SECRET_MANAGER_FLAG=""
IDENTITY_ARN=""
START_PHASE=1

while [[ $# -gt 0 ]]; do
  case $1 in
    --secure-boot) SECURE_BOOT_FLAG="--secure-boot"; shift ;;
    --debug) DEBUG_FLAG="--debug"; shift ;;
    --timeout) TIMEOUT="$2"; shift; shift ;;
    --no-cleanup) NO_CLEANUP=true; shift ;;
    --skip-sg-update) SKIP_SG_UPDATE=true; shift ;;
    --authorize-my-ip) AUTHORIZE_MY_IP=true; shift ;; # CI/CD: auto-allowlist the runner's public IP on 5432
    --admin-role-arn) ADMIN_ROLE_ARN_OVERRIDE="$2"; shift; shift ;;
    --vpc-id) VPC_ID_FLAG="--vpc-id $2"; shift; shift ;;
    --start-phase) START_PHASE="$2"; shift; shift ;; # resume a prior --no-cleanup run
    --secrets-manager)
      SECRET_MANAGER_FLAG="true"
      shift
      if [[ $# -gt 0 ]] && [[ "$1" != --* ]]; then
        IDENTITY_ARN="$1"; shift
        validate_secret_arn "$IDENTITY_ARN"
      fi
      ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

if [ -n "$SECRET_MANAGER_FLAG" ] && [ -z "$SECURE_BOOT_FLAG" ]; then
  echo "Error: --secrets-manager requires --secure-boot"
  exit 1
fi

if [ "$AUTHORIZE_MY_IP" = true ] && [ "$SKIP_SG_UPDATE" = true ]; then
  echo "Error: --authorize-my-ip and --skip-sg-update are mutually exclusive"
  exit 1
fi

case "$START_PHASE" in
  1|2|3) ;;
  *) echo "Error: --start-phase must be 1, 2, or 3 (got '$START_PHASE')"; exit 1 ;;
esac

PHASE1_RESULT="SKIP"
PHASE2_RESULT="SKIP"
PHASE3_RESULT="SKIP"
PHASE4_RESULT="SKIP"

CLIENT_CA_FILE=""
CLIENT_CERT_FILE=""
CLIENT_KEY_FILE=""

mkdir -p "$ARTIFACTS_DIR"
if [ "$START_PHASE" -eq 1 ]; then
  echo '{}' > "$RESOURCES_FILE"
elif [ ! -f "$RESOURCES_FILE" ]; then
  echo "Error: --start-phase $START_PHASE needs a prior run's $RESOURCES_FILE (from --no-cleanup)."
  exit 1
fi

load_provisioned_state() {
  AMI_ID=$(jq -r '.AMI_ID // empty' "$RESOURCES_FILE")
  ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE")
  INSTANCE_PROFILE_NAME=$(jq -r '.INSTANCE_PROFILE_NAME // empty' "$RESOURCES_FILE")
  VOLUME_ID=$(jq -r '.VOLUME_ID // empty' "$RESOURCES_FILE")
  INSTANCE_ID=$(jq -r '.INSTANCE_ID // empty' "$RESOURCES_FILE")
  SG_ID=$(jq -r '.SECURITY_GROUP_ID // empty' "$RESOURCES_FILE")
  if [ -z "$INSTANCE_ID" ]; then
    echo "Error: no INSTANCE_ID in $RESOURCES_FILE; cannot resume at phase $START_PHASE."
    return 1
  fi
  read -r PRIVATE_IP PUBLIC_IP < <(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].[PrivateIpAddress,PublicIpAddress]' --output text 2>/dev/null)
  if [ -z "$PUBLIC_IP" ] || [ "$PUBLIC_IP" = "None" ]; then
    echo "Error: instance $INSTANCE_ID has no public IP (gone, or launched without --public)."
    return 1
  fi
  echo "Resuming at phase $START_PHASE with instance $INSTANCE_ID (public $PUBLIC_IP)."
  if [ "$AUTHORIZE_MY_IP" = true ]; then
    authorize_my_ip "$SG_ID" || return 1
  elif [ "$SKIP_SG_UPDATE" = false ]; then
    print_sg_authorization_notice "$SG_ID"
  fi
}

retrieve_client_certs() {
  # Suppress xtrace so the client private key isn't echoed; RETURN trap restores it.
  case "$-" in *x*) trap 'set -x; trap - RETURN' RETURN; set +x ;; esac

  echo "Retrieving client certificate bundle from Secrets Manager..."
  local SECRET_ARN
  SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE")
  if [ -z "$SECRET_ARN" ]; then
    echo "ERROR: SECRET_ARN not found in resources.json"
    return 1
  fi

  local SECRET_JSON
  SECRET_JSON=$(aws secretsmanager get-secret-value \
    --secret-id "$SECRET_ARN" \
    --query 'SecretString' \
    --output text) || { echo "ERROR: Failed to retrieve secret from Secrets Manager"; return 1; }

  local CA_B64 CERT_B64 KEY_B64
  CA_B64=$(echo "$SECRET_JSON" | jq -r '.ca_cert // empty')
  CERT_B64=$(echo "$SECRET_JSON" | jq -r '.client_cert // empty')
  KEY_B64=$(echo "$SECRET_JSON" | jq -r '.client_key // empty')

  if [ -z "$CA_B64" ] || [ -z "$CERT_B64" ] || [ -z "$KEY_B64" ]; then
    echo "ERROR: Client certificate bundle is missing required fields (ca_cert, client_cert, client_key)"
    return 1
  fi

  CLIENT_CA_FILE=$(mktemp)
  CLIENT_CERT_FILE=$(mktemp)
  CLIENT_KEY_FILE=$(mktemp)

  echo "$CA_B64" | base64 -d > "$CLIENT_CA_FILE" || { echo "ERROR: Failed to decode ca_cert"; return 1; }
  echo "$CERT_B64" | base64 -d > "$CLIENT_CERT_FILE" || { echo "ERROR: Failed to decode client_cert"; return 1; }
  echo "$KEY_B64" | base64 -d > "$CLIENT_KEY_FILE" || { echo "ERROR: Failed to decode client_key"; return 1; }

  chmod 0600 "$CLIENT_KEY_FILE"
  echo "Client certificates written to temp files."
}

wait_for_ssm() {
  local INSTANCE_ID=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for SSM connectivity on $INSTANCE_ID (timeout: ${TIMEOUT}s)..."
  while true; do
    local SSM_STATUS
    SSM_STATUS=$(aws ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
      --query 'InstanceInformationList[0].PingStatus' \
      --output text 2>/dev/null || echo "None")
    if [ "$SSM_STATUS" = "Online" ]; then
      echo "SSM agent is online on $INSTANCE_ID"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for SSM on $INSTANCE_ID after ${ELAPSED}s"
      return 1
    fi
    sleep 10
  done
}

run_ssm_command() {
  local INSTANCE_ID=$1
  local COMMAND=$2
  local TMPJSON
  TMPJSON=$(mktemp)
  jq -n --arg id "$INSTANCE_ID" --arg cmd "$COMMAND" \
    '{InstanceIds: [$id], DocumentName: "AWS-RunShellScript", Parameters: {commands: [$cmd]}}' > "$TMPJSON"
  local CMD_ID
  CMD_ID=$(aws ssm send-command --cli-input-json "file://$TMPJSON" \
    --query 'Command.CommandId' \
    --output text)
  rm -f "$TMPJSON"

  aws ssm wait command-executed \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" 2>/dev/null || true

  aws ssm get-command-invocation \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" \
    --query 'StandardOutputContent' \
    --output text
}

wait_for_postgresql_ssm() {
  local INSTANCE_ID=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for PostgreSQL via SSM on $INSTANCE_ID (timeout: ${TIMEOUT}s)..."
  while true; do
    local RESULT
    RESULT=$(run_ssm_command "$INSTANCE_ID" "sudo -u postgres psql -c \"SELECT 1\" -t -A" 2>/dev/null || echo "")
    if [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ]; then
      echo "PostgreSQL is available on $INSTANCE_ID (via SSM)"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for PostgreSQL via SSM on $INSTANCE_ID after ${ELAPSED}s"
      return 1
    fi
    sleep 15
  done
}

run_sql_ssm() {
  local INSTANCE_ID=$1
  local SQL=$2
  run_ssm_command "$INSTANCE_ID" "sudo -u postgres psql -c \"$SQL\" -t -A"
}

wait_for_postgresql_mtls() {
  local HOST=$1
  local TIMEOUT=$2
  local START
  START=$(date +%s)
  echo "Waiting for PostgreSQL via mTLS on $HOST (timeout: ${TIMEOUT}s)..."
  while true; do
    if psql "sslmode=verify-ca sslcert=$CLIENT_CERT_FILE sslkey=$CLIENT_KEY_FILE sslrootcert=$CLIENT_CA_FILE host=$HOST port=5432 dbname=postgres user=postgres-client" -c "SELECT 1" -t -A &>/dev/null; then
      echo "PostgreSQL is available on $HOST (via mTLS)"
      return 0
    fi
    local ELAPSED=$(( $(date +%s) - START ))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "Timeout waiting for PostgreSQL mTLS on $HOST after ${ELAPSED}s"
      return 1
    fi
    sleep 15
  done
}

run_sql_mtls() {
  local HOST=$1
  local SQL=$2
  psql "sslmode=verify-ca sslcert=$CLIENT_CERT_FILE sslkey=$CLIENT_KEY_FILE sslrootcert=$CLIENT_CA_FILE host=$HOST port=5432 dbname=postgres user=postgres-client" -c "$SQL" -t -A
}

cleanup() {
  echo ""
  echo "=== Phase 4: Cleanup ==="

  local SECRET_ARN
  SECRET_ARN=$(jq -r '.SECRET_ARN // empty' "$RESOURCES_FILE" 2>/dev/null || true)
  local ROLE_NAME
  ROLE_NAME=$(jq -r '.ROLE_NAME // empty' "$RESOURCES_FILE" 2>/dev/null || true)

  if [ -n "$SECRET_ARN" ]; then
    echo "Deleting Secrets Manager secret: $SECRET_ARN"
    if ! aws secretsmanager delete-secret --secret-id "$SECRET_ARN" --force-delete-without-recovery 2>&1; then
      echo "Warning: Failed to delete Secrets Manager secret (non-critical)"
    fi
  fi

  if [ -n "$ROLE_NAME" ]; then
    echo "Removing inline IAM policy SecretsManagerClientCertAccess from role $ROLE_NAME..."
    if ! aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "SecretsManagerClientCertAccess" 2>&1; then
      echo "Warning: Failed to remove inline IAM policy (non-critical)"
    fi
  fi

  if [ -n "$CLIENT_CA_FILE" ] && [ -f "$CLIENT_CA_FILE" ]; then
    rm -f "$CLIENT_CA_FILE"
  fi
  if [ -n "$CLIENT_CERT_FILE" ] && [ -f "$CLIENT_CERT_FILE" ]; then
    rm -f "$CLIENT_CERT_FILE"
  fi
  if [ -n "$CLIENT_KEY_FILE" ] && [ -f "$CLIENT_KEY_FILE" ]; then
    rm -f "$CLIENT_KEY_FILE"
  fi

  if [ -f "$RESOURCES_FILE" ]; then
    "$SCRIPT_DIR/clean.sh" && PHASE4_RESULT="PASS" || PHASE4_RESULT="FAIL"
  else
    echo "No resources file found, nothing to clean up."
    PHASE4_RESULT="PASS"
  fi
}

echo "Validating AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are invalid or expired."
  exit 1
fi
echo "AWS credentials are valid."

phase1() {
  # KMS key first: ARN is pinned into the image (PCR4). Bootstrap policy here; gated in Step 4.
  echo "Step 1: Creating KMS key (bootstrap policy)..."
  ADMIN_ROLE_ARN="${ADMIN_ROLE_ARN_OVERRIDE:-$(aws sts get-caller-identity --query 'Arn' --output text)}"
  OUTPUT=$("$SCRIPT_DIR/steps/02a_create_kms_key.sh" -a "$ADMIN_ROLE_ARN")
  KMS_KEY_ARN=$(echo "$OUTPUT" | grep -oP 'KMS key created with ARN: \K.*')
  [ -z "$KMS_KEY_ARN" ] && { echo "Failed to extract KMS key ARN"; return 1; }
  update_resource "KMS_KEY_ARN" "$KMS_KEY_ARN"
  echo "KMS Key ARN: $KMS_KEY_ARN"

  echo "Step 2: Creating AMI..."
  CREATE_AMI_ARGS="$SECURE_BOOT_FLAG $DEBUG_FLAG"
  if [ -n "$SECRET_MANAGER_FLAG" ]; then
    if [ -z "$IDENTITY_ARN" ]; then
      echo "Generating and uploading a golden signing identity..."
      IDENTITY_ARN=$(generate_and_upload_identity "nitrotpm-sb-identity") \
        || { echo "Failed to generate signing identity"; return 1; }
      update_resource "IDENTITY_ARN" "$IDENTITY_ARN"
      echo "Identity uploaded (no private key written to disk). ARN: $IDENTITY_ARN"
    fi
    echo "Rebuilding reproducible UEFI envelope from persisted identity..."
    rebuild_sb_envelope_from_identity "$PROJECT_DIR/sb-keys" "$PROJECT_DIR" "$IDENTITY_ARN" \
      || { echo "Failed to rebuild secure boot envelope"; return 1; }
    CREATE_AMI_ARGS="$CREATE_AMI_ARGS --identity-arn $IDENTITY_ARN"
  elif [ -n "$SECURE_BOOT_FLAG" ]; then
    echo "Generating ephemeral secure boot keys (non-reproducible)..."
    generate_local_sb_keys "$PROJECT_DIR/sb-keys" "$PROJECT_DIR" \
      || { echo "Failed to generate secure boot keys"; return 1; }
  fi
  OUTPUT=$("$SCRIPT_DIR/steps/00_create_ami.sh" $CREATE_AMI_ARGS)
  CREATE_AMI_RC=$?
  if [ -n "$SECURE_BOOT_FLAG" ] && [ -d "$PROJECT_DIR/sb-keys" ]; then
    rm -rf "$PROJECT_DIR/sb-keys"
  fi
  [ $CREATE_AMI_RC -ne 0 ] && { echo "AMI creation failed"; return 1; }
  AMI_ID=$(echo "$OUTPUT" | grep -oP 'ami-[a-z0-9]+')
  [ -z "$AMI_ID" ] && { echo "Failed to extract AMI ID"; return 1; }
  update_resource "AMI_ID" "$AMI_ID"
  echo "AMI ID: $AMI_ID"

  echo "Step 3: Setting up IAM..."
  ROLE_NAME="TpmAttestationRole"
  INSTANCE_PROFILE_NAME="TpmAttestationProfile"
  if [ -n "$DEBUG_FLAG" ]; then
    "$SCRIPT_DIR/steps/01_create_instance_profile.sh" -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME" --debug
  else
    "$SCRIPT_DIR/steps/01_create_instance_profile.sh" -r "$ROLE_NAME" -p "$INSTANCE_PROFILE_NAME"
  fi
  update_resource "ROLE_NAME" "$ROLE_NAME"
  update_resource "INSTANCE_PROFILE_NAME" "$INSTANCE_PROFILE_NAME"

  # Wrap the DEK while the bootstrap policy still grants Encrypt, BEFORE finalize strips it.
  echo "Step 4: Creating symmetric key..."
  local KEY_TMPDIR
  KEY_TMPDIR=$(mktemp -d)
  chmod 700 "$KEY_TMPDIR"
  local KEY_FILE="$KEY_TMPDIR/symmetric_key"
  "$SCRIPT_DIR/steps/03_create_symmetric_key.sh" -k "$KMS_KEY_ARN" --plaintext-key-out "$KEY_FILE" \
    || { rm -rf "$KEY_TMPDIR"; return 1; }

  # Real policy: Decrypt gated on PCRs; kms:PutKeyPolicy and kms:Encrypt revoked, key immutable from here.
  echo "Step 5: Finalizing KMS key policy with PCR conditions..."
  INSTANCE_ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)
  PCR_DIR=$(resolve_pcr_dir "$SCRIPT_DIR/.." "$SECURE_BOOT_FLAG")
  "$SCRIPT_DIR/steps/02b_finalize_kms_policy.sh" -k "$KMS_KEY_ARN" -r "$INSTANCE_ROLE_ARN" -a "$ADMIN_ROLE_ARN" -m "$PCR_DIR" \
    || { rm -rf "$KEY_TMPDIR"; echo "Failed to finalize KMS key policy"; return 1; }

  echo "Step 6: Creating certificates..."
  "$SCRIPT_DIR/steps/05a_create_certificates.sh" -r "$ROLE_NAME" --symmetric-key "$KEY_FILE" \
    || { rm -rf "$KEY_TMPDIR"; return 1; }
  rm -rf "$KEY_TMPDIR"

  echo "Step 7: Creating EBS volume..."
  AVAILABILITY_ZONE=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
  OUTPUT=$("$SCRIPT_DIR/steps/04_create_ebs_volume.sh" -z "$AVAILABILITY_ZONE")
  VOLUME_ID=$(echo "$OUTPUT" | grep -oP 'Volume ID: \K.*')
  [ -z "$VOLUME_ID" ] && { echo "Failed to extract Volume ID"; return 1; }
  update_resource "VOLUME_ID" "$VOLUME_ID"
  echo "Volume ID: $VOLUME_ID"

  echo "Step 8: Launching instance..."
  OUTPUT=$(run_instance_step "$AMI_ID" "$INSTANCE_PROFILE_NAME" "$VOLUME_ID" "$VPC_ID_FLAG" "$DEBUG_FLAG")
  INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
  PRIVATE_IP=$(echo "$OUTPUT" | grep -oP 'Private IP: \K.*')
  PUBLIC_IP=$(echo "$OUTPUT" | grep -oP 'Public IP: \K.*')
  SG_ID=$(echo "$OUTPUT" | grep -oP 'Security Group ID: \K.*')
  [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] || [ -z "$SG_ID" ] && { echo "Failed to extract instance details"; return 1; }
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  update_resource "SECURITY_GROUP_ID" "$SG_ID"
  echo "Instance ID: $INSTANCE_ID, Private IP: $PRIVATE_IP, Public IP: $PUBLIC_IP"
  if [ "$AUTHORIZE_MY_IP" = true ]; then
    authorize_my_ip "$SG_ID" || return 1
  elif [ "$SKIP_SG_UPDATE" = false ]; then
    print_sg_authorization_notice "$SG_ID"
  fi
}

if [ "$START_PHASE" -le 1 ]; then
  echo ""
  echo "=== Phase 1: Provision ==="
  if phase1; then
    PHASE1_RESULT="PASS"
    echo "Phase 1: PASS"
  else
    PHASE1_RESULT="FAIL"
    echo "Phase 1: FAIL"
    if [ "$NO_CLEANUP" = true ]; then
      echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
      echo "Resource file: $RESOURCES_FILE"
      PHASE4_RESULT="SKIP"
    else
      cleanup
    fi
    echo ""
    echo "=== E2E Test Summary ==="
    echo "Phase 1 (Provision):              $PHASE1_RESULT"
    echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
    echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
    echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
    exit 1
  fi
else
  if ! load_provisioned_state; then
    exit 1
  fi
fi

phase2() {
  if [ "$SKIP_SG_UPDATE" = false ] && [ "$AUTHORIZE_MY_IP" = false ] && [ -t 0 ]; then
    read -r -p "Add your host to SG $SG_ID:5432 (see above), then press Enter to validate... " _
  fi

  retrieve_client_certs || return 1
  wait_for_postgresql_mtls "$PUBLIC_IP" "$TIMEOUT" || return 1

  # Verify SELECT 1 via mTLS
  echo "Verifying PostgreSQL with SELECT 1 (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT 1;")
  [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ] || { echo "SELECT 1 failed (mTLS): got '$RESULT'"; return 1; }
  echo "SELECT 1 (mTLS): OK"

  echo "Writing test data (mTLS)..."
  run_sql_mtls "$PUBLIC_IP" "CREATE TABLE IF NOT EXISTS e2e_test (id serial PRIMARY KEY, value text);"
  run_sql_mtls "$PUBLIC_IP" "INSERT INTO e2e_test (value) VALUES ('persistence-check');"

  echo "Reading back test data (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Read back failed (mTLS): got '$RESULT'"; return 1; }
  echo "Test data verified (mTLS): OK"

  if [ -n "$DEBUG_FLAG" ]; then
    echo "Debug mode: running SSM-based checks..."
    wait_for_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1
    wait_for_postgresql_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1

    echo "Verifying PostgreSQL with SELECT 1 (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT 1;")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "1" ] || { echo "SELECT 1 failed (SSM): got '$RESULT'"; return 1; }
    echo "SELECT 1 (SSM): OK"

    echo "Reading back test data (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT value FROM e2e_test WHERE value='persistence-check';")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "persistence-check" ] || { echo "Read back failed (SSM): got '$RESULT'"; return 1; }
    echo "Test data verified (SSM): OK"
  fi
}

if [ "$START_PHASE" -le 2 ]; then
  echo ""
  echo "=== Phase 2: First Boot Validation ==="
  if phase2; then
    PHASE2_RESULT="PASS"
    echo "Phase 2: PASS"
  else
    PHASE2_RESULT="FAIL"
    echo "Phase 2: FAIL"
    if [ "$NO_CLEANUP" = true ]; then
      echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
      echo "Resource file: $RESOURCES_FILE"
      PHASE4_RESULT="SKIP"
    else
      cleanup
    fi
    echo ""
    echo "=== E2E Test Summary ==="
    echo "Phase 1 (Provision):              $PHASE1_RESULT"
    echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
    echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
    echo "Phase 4 (Cleanup):                $PHASE4_RESULT"
    exit 1
  fi
fi

echo ""
echo "=== Phase 3: Persistence Validation ==="

phase3() {
  if [ -z "$CLIENT_CA_FILE" ] || [ ! -f "$CLIENT_CA_FILE" ]; then
    retrieve_client_certs || return 1
  fi

  echo "Terminating first instance $INSTANCE_ID..."
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID"
  aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
  echo "First instance terminated."

  echo "Waiting for EBS volume to become available..."
  aws ec2 wait volume-available --volume-ids "$VOLUME_ID"

  echo "Launching second instance..."
  OUTPUT=$(run_instance_step "$AMI_ID" "$INSTANCE_PROFILE_NAME" "$VOLUME_ID" "$VPC_ID_FLAG" "$DEBUG_FLAG")
  INSTANCE_ID=$(echo "$OUTPUT" | grep -oP 'Instance ID: \K.*')
  PRIVATE_IP=$(echo "$OUTPUT" | grep -oP 'Private IP: \K.*')
  PUBLIC_IP=$(echo "$OUTPUT" | grep -oP 'Public IP: \K.*')
  SG_ID2=$(echo "$OUTPUT" | grep -oP 'Security Group ID: \K.*')
  [ -z "$INSTANCE_ID" ] || [ -z "$PUBLIC_IP" ] && { echo "Failed to launch second instance"; return 1; }
  update_resource "INSTANCE_ID" "$INSTANCE_ID"
  [ -n "$SG_ID2" ] && update_resource "SECURITY_GROUP_ID" "$SG_ID2"
  echo "Second instance: $INSTANCE_ID, Private IP: $PRIVATE_IP, Public IP: $PUBLIC_IP"

  wait_for_postgresql_mtls "$PUBLIC_IP" "$TIMEOUT" || return 1

  # Verify persisted data via mTLS
  echo "Verifying persisted test data (mTLS)..."
  RESULT=$(run_sql_mtls "$PUBLIC_IP" "SELECT value FROM e2e_test WHERE value='persistence-check';")
  [ "$RESULT" = "persistence-check" ] || { echo "Persistence check failed (mTLS): got '$RESULT'"; return 1; }
  echo "Persistence verified (mTLS): OK"

  if [ -n "$DEBUG_FLAG" ]; then
    echo "Debug mode: running SSM-based persistence checks..."
    wait_for_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1
    wait_for_postgresql_ssm "$INSTANCE_ID" "$TIMEOUT" || return 1

    echo "Verifying persisted test data (SSM)..."
    RESULT=$(run_sql_ssm "$INSTANCE_ID" "SELECT value FROM e2e_test WHERE value='persistence-check';")
    [ "$(echo "$RESULT" | tr -d '[:space:]')" = "persistence-check" ] || { echo "Persistence check failed (SSM): got '$RESULT'"; return 1; }
    echo "Persistence verified (SSM): OK"
  fi
}

if phase3; then
  PHASE3_RESULT="PASS"
  echo "Phase 3: PASS"
else
  PHASE3_RESULT="FAIL"
  echo "Phase 3: FAIL"
fi

if [ "$NO_CLEANUP" = true ]; then
  echo ""
  echo "=== Phase 4: Cleanup ==="
  echo "Skipping cleanup (--no-cleanup). Resources preserved for debugging."
  echo "Resource file: $RESOURCES_FILE"
  echo "Run ./scripts/clean.sh manually when done."
  PHASE4_RESULT="SKIP"
else
  cleanup
fi

echo ""
echo "=== E2E Test Summary ==="
echo "Phase 1 (Provision):              $PHASE1_RESULT"
echo "Phase 2 (First Boot Validation):  $PHASE2_RESULT"
echo "Phase 3 (Persistence Validation): $PHASE3_RESULT"
echo "Phase 4 (Cleanup):                $PHASE4_RESULT"

for RESULT in "$PHASE1_RESULT" "$PHASE2_RESULT" "$PHASE3_RESULT" "$PHASE4_RESULT"; do
  if [ "$RESULT" = "FAIL" ]; then
    exit 1
  fi
done

echo "All executed phases PASSED."
