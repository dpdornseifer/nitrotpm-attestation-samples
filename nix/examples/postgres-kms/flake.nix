{
  description = "Example of TEE with LUKS-encrypted PostgreSQL data volume";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nitro-tee.url = "path:../..";
  };
  outputs = { self, nixpkgs, flake-utils, nitro-tee, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
          lib = nixpkgs.lib;

          # Pinned at build time into the measured store closure: a different key requires a rebuild (changes PCR4, rejected by the policy).
          # git-tracked on purpose — git+file:// flake refs only see tracked paths; empty = buildable but boots fail-closed.
          kmsKeyArn =
            if !builtins.pathExists ./kms-key-arn.txt then
              throw ("kms-key-arn.txt is missing from the flake source. It must be git-tracked: "
                + "a git+file:// flake ref only sees tracked paths. "
                + "Run: git add nix/examples/postgres-kms/kms-key-arn.txt")
            else
              let
                raw = lib.removeSuffix "\n" (builtins.readFile ./kms-key-arn.txt);
                pattern = "arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}";
              in
              if raw == "" || builtins.match pattern raw != null then raw
              else
                throw ("kms-key-arn.txt must hold one full KMS key ARN with no surrounding "
                  + "whitespace, or be empty to build unpinned. Got: '" + raw + "'");

          kmsInitScript = pkgs.callPackage ./kms-init.nix { inherit nitro-tee kmsKeyArn; };
          luksInitScript = pkgs.callPackage ./luks-init.nix { };
          certInitScript = pkgs.callPackage ./cert-init.nix { };
          imdsCredentialsScript = pkgs.callPackage ./imds-credentials.nix { };

          commonUserConfig = { config, pkgs, lib, ... }: {
            users.groups.tpm = {};
            users.groups.kms-init = {};

            users.users.kms-init = {
              isSystemUser = true;
              group = "kms-init";
              extraGroups = [ "tpm" ];
            };


            system.stateVersion = "24.11";

            services.udev.extraRules = ''
              KERNEL=="tpm0", OWNER="root", GROUP="tpm", MODE="0660"
            '';

            systemd.services.kms-init = {
              description = "Initialize KMS and decrypt symmetric key";
              wantedBy = [ "multi-user.target" ];
              requires = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = kmsInitScript;
                RemainAfterExit = true;

                User = "kms-init";
                RuntimeDirectory = "kms-init";
                RuntimeDirectoryMode = "0750";
                UMask = "0027";

                ProtectSystem = "strict";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectHome = true;
                ProtectHostname = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";

                PrivateTmp = true;
                PrivateUsers = true;

                DevicePolicy = "closed";
                DeviceAllow = [ "/dev/tpm0 rw" ];

                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;

                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RemoveIPC = true;

                CapabilityBoundingSet = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources"];
                SystemCallErrorNumber = "EPERM";
              };
            };

            boot.kernelModules = [ "dm-integrity" ];

            # First-boot integrity-tag wipe (~90s/10 GiB) outlasts the 90s default device job timeout, discarding data.mount before luks-unlock finishes; scoped to this device only.
            systemd.units."dev-mapper-data.device" = {
              overrideStrategy = "asDropin";
              text = ''
                [Unit]
                JobRunningTimeoutSec=1800s
              '';
            };

            systemd.services.luks-unlock = {
              description = "Unlock LUKS-encrypted data volume";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = luksInitScript;
                RemainAfterExit = true;
                # First-boot --integrity wipe is a full-device write; 1800s covers large volumes.
                TimeoutStartSec = "1800s";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
              };
            };

            systemd.mounts = [{
              what = "/dev/mapper/data";
              where = "/data";
              type = "ext4";
              wantedBy = [ "multi-user.target" ];
              requires = [ "luks-unlock.service" ];
              after = [ "luks-unlock.service" ];
              # Operator-attachable volume; noexec/nosuid safe because PostgreSQL extensions load from the read-only store, not $PGDATA.
              options = "defaults,nodev,nosuid,noexec";
              unitConfig = {
                # Avoid cycle: data.mount → luks-unlock → kms-init → basic.target → local-fs.target → data.mount
                DefaultDependencies = false;
              };
            }];

            systemd.services.cert-init = {
              description = "Decrypt server certificate bundle for PostgreSQL mTLS";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              before = [ "postgresql.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = certInitScript;
                RemainAfterExit = true;
                RuntimeDirectory = "postgresql-certs";
                RuntimeDirectoryMode = "0750";

                ReadOnlyPaths = [ "/run/kms-init" ];

                ProtectSystem = "strict";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectHome = true;
                ProtectHostname = true;

                PrivateTmp = true;

                NoNewPrivileges = true;
                RestrictSUIDSGID = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
              };
            };

            systemd.services.postgresql-datadir-init = {
              description = "Create PostgreSQL data directory on encrypted volume";
              wantedBy = [ "multi-user.target" ];
              requires = [ "data.mount" ];
              after = [ "data.mount" ];
              before = [ "postgresql.service" ];
              unitConfig.DefaultDependencies = false;
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ExecStart = "${pkgs.coreutils}/bin/install -d -o postgres -g postgres -m 0700 /data/postgresql";
              };
            };

            services.postgresql = {
              enable = true;
              dataDir = "/data/postgresql";
              # Defense in depth: per-page checksums catch torn/spliced pages that slip past dm-integrity.
              initdbArgs = [ "--data-checksums" ];
              initialScript = pkgs.writeText "init-postgres-client.sql" ''
                CREATE ROLE "postgres-client" WITH LOGIN;
                GRANT ALL ON SCHEMA public TO "postgres-client";
                -- Disable the bootstrap superuser; nothing re-logs in as postgres post-init.
                ALTER ROLE postgres NOLOGIN;
              '';
              settings = {
                ssl = "on";
                ssl_cert_file = "/run/postgresql-certs/server.crt";
                ssl_key_file = "/run/postgresql-certs/server.key";
                ssl_ca_file = "/run/postgresql-certs/ca.crt";
                listen_addresses = lib.mkForce "*";
              };
              # Only CN=postgres-client maps to a role (via the mtls map); the superuser is
              # rejected over TCP. Closes the network-superuser path; the deployer still
              # holds the CA key — see README Production Considerations.
              identMap = ''
                mtls /^postgres-client$ postgres-client
              '';
              authentication = lib.mkForce ''
                local all all peer
                hostssl all postgres        0.0.0.0/0 reject
                hostssl all postgres        ::/0      reject
                hostssl all postgres-client 0.0.0.0/0 cert clientcert=verify-full map=mtls
                hostssl all postgres-client ::/0      cert clientcert=verify-full map=mtls
              '';
            };

            systemd.services.postgresql = {
              requires = [ "data.mount" "postgresql-datadir-init.service" "cert-init.service" ];
              after = [ "data.mount" "postgresql-datadir-init.service" "cert-init.service" ];
              serviceConfig = {
                ReadOnlyPaths = [ "/run/postgresql-certs" ];
              };
            };

            networking.firewall = {
              allowedTCPPorts = [ 5432 ];
              # Only kms-init may reach IMDS; all other users are dropped.
              extraCommands = "
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner kms-init -j ACCEPT
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -j DROP
              ";
            };
          };

          debugUserConfig = { config, pkgs, lib, ... }: {
            environment.systemPackages = [
              (pkgs.runCommand "imds-credentials" {} ''
                mkdir -p $out/bin
                cp ${imdsCredentialsScript} $out/bin/imds-credentials.sh
              '')
            ];

            services.amazon-ssm-agent.enable = true;

            # SSM runs as root and needs IMDS; insert ACCEPT before the production DROP.
            networking.firewall.extraCommands = lib.mkAfter "
              ${pkgs.iptables}/bin/iptables -I OUTPUT -d 169.254.169.254 -m owner --uid-owner root -j ACCEPT
            ";
          };
        in
        {
          packages = {
            # Secure boot signing is a post-build step (see sign-efi-image).
            raw-image = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = false;
            };

            # WARNING: debug build enables console/operator access and bypasses security!
            raw-image-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = { imports = [ commonUserConfig debugUserConfig ]; };
              isDebug = true;
            };
          };

          apps = {
            boot-uefi-qemu = nitro-tee.apps.${system}.boot-uefi-qemu;
            create-ami = nitro-tee.apps.${system}.create-ami;
            sign-efi-image = nitro-tee.apps.${system}.sign-efi-image;
            compute-pcrs = nitro-tee.apps.${system}.compute-pcrs;
            generate-uefi-vars = nitro-tee.apps.${system}.generate-uefi-vars;
          };
        }
      );
}
