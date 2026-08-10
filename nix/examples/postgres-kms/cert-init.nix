{
  pkgs,
  ...
}:
pkgs.writeScript "cert-init.sh" ''
  #!${pkgs.bash}/bin/bash
  set -euo pipefail

  # kms-init persisted the user-data, so no IMDS access is needed here
  USER_DATA=$(${pkgs.coreutils}/bin/cat /run/kms-init/user_data.json)
  SERVER_CERT_BUNDLE=$(echo "$USER_DATA" | ${pkgs.jq}/bin/jq -re .server_cert_bundle)

  CERTS_DIR=/run/postgresql-certs

  # Decrypt and extract ONLY the three expected members (05a bundles exactly
  # these, flat) so a forged bundle can't drop extra files. Ownership/mode fixup
  # runs in cert-init-perms.service (privileged, no parsing).
  echo "$SERVER_CERT_BUNDLE" | ${pkgs.coreutils}/bin/base64 -d \
    | ${pkgs.openssl}/bin/openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/run/kms-init/symmetric_key \
    | ${pkgs.gnutar}/bin/tar xf - -C "$CERTS_DIR/" --no-wildcards ca.crt server.crt server.key

  # Re-emit as canonical PEM: openssl skips leading garbage, so a parse-only check
  # passes an ELF/PEM-polyglot ca.crt. Rewriting from the parsed object strips any
  # non-PEM prefix and fails closed on non-PEM input.
  reemit() {
    local f="$CERTS_DIR/$1"; shift
    "$@" -in "$f" -out "$f.tmp"
    ${pkgs.coreutils}/bin/mv -f "$f.tmp" "$f"
  }
  reemit ca.crt     ${pkgs.openssl}/bin/openssl x509
  reemit server.crt ${pkgs.openssl}/bin/openssl x509
  reemit server.key ${pkgs.openssl}/bin/openssl pkey
''
