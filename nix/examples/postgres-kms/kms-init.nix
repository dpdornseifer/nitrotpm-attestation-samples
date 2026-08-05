{
  pkgs,
  system,
  nitro-tee,
  kmsKeyArn,
  ...
}:
pkgs.writeScript "kms-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # Sourced from the store, covered by dm-verity and measured into PCR4.
  . ${./kms-verify.sh}

  # KMS key fixed at build time; empty = buildable but unbootable (see kms-verify.sh).
  PINNED_KMS_KEY_ARN='${kmsKeyArn}'

  TOKEN=$(${pkgs.curl}/bin/curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  USER_DATA=$(${pkgs.curl}/bin/curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data)

  echo "$USER_DATA" > /run/kms-init/user_data.json

  # Default to "" so an absent key_id reaches kms_verify_pinned_key_id with a clear error, not a bare jq failure.
  KEY_ID=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -r '.key_id // ""')
  CIPHERTEXT=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .ciphertext)

  # user-data is unmeasured; enforce the pinned ARN to prevent key substitution.
  kms_verify_pinned_key_id "$PINNED_KMS_KEY_ARN" "$KEY_ID" \
    || { echo "FATAL: refusing to decrypt against an unpinned or substituted KMS key" >&2; exit 1; }

  # Decrypt against PINNED_KMS_KEY_ARN, not $KEY_ID: the guarantee comes from the measurement.
  SYMMETRIC_KEY=$(${nitro-tee.packages.${system}.kms-decrypt-app}/bin/nitro-tpm-kms-decrypt --key-id "$PINNED_KMS_KEY_ARN" "$CIPHERTEXT")
  echo "$SYMMETRIC_KEY" > /run/kms-init/symmetric_key
''
