{
  pkgs,
  lib,
  modulesPath,
  ...
}: {
  imports = [
    "${toString modulesPath}/profiles/minimal.nix"
    "${toString modulesPath}/profiles/qemu-guest.nix"
  ];

  system.image = {
    id = lib.mkDefault "nixos-tee";
    version = "1";
  };

  boot.enableContainers = lib.mkDefault false;
  boot.initrd.systemd.enable = lib.mkDefault true;

  documentation.info.enable = lib.mkDefault false;

  networking.useNetworkd = lib.mkDefault true;
  networking.firewall.enable = lib.mkDefault true;

  nix.enable = false;

  programs.command-not-found.enable = lib.mkDefault false;
  programs.less.lessopen = lib.mkDefault null;

    # Secure network defaults
  systemd.network = {
    enable = lib.mkDefault true;
    networks."10-secure" = {
      matchConfig.Name = lib.mkDefault "*";
      networkConfig = {
        DHCP = lib.mkDefault "ipv4";
        IPv6AcceptRA = lib.mkDefault false;
        LinkLocalAddressing = lib.mkDefault "no";
        LLMNR = lib.mkDefault false;
        MulticastDNS = lib.mkDefault false;
        DNSOverTLS = lib.mkDefault "opportunistic";
        DNSSEC = lib.mkDefault "allow-downgrade";
      };
    };
  };

  # Disable auto-login
  services.getty.autologinUser = lib.mkForce null;
  services.sshd.enable = lib.mkForce false;
  services.udisks2.enable = false; # udisks has become too bloated to have in a headless system

  # An operator-attached EBS volume is auto-probed as root by udev, and pvscan parses its
  # metadata. Do NOT disable services.lvm to stop that: lvm2 also ships the generic
  # device-mapper udev rules, and without 95-dm-notify libdevmapper's cookie is never
  # released (luksFormat hangs until its timeout) and without 13-dm-disk there is no
  # /dev/mapper/data for data.mount. Reject every device for LVM tools instead.
  environment.etc."lvm/lvm.conf".text = lib.mkAfter ''
    devices { global_filter = [ "r|.*|" ] }
  '';

  # Subsystems nothing here uses, carrying unpatched CVEs in the floating kernel.
  # dm_mod is deliberately absent: dm-crypt and dm-verity depend on it.
  boot.blacklistedKernelModules = [
    "bcache" # parses attacker-supplied journal metadata on udev auto-registration
    "sctp"
    "openvswitch"
    "can"
    "can-raw"
    "can-bcm"
    "can-gw"
    "can-j1939"
    "vcan"
    "mpls_router"
    "mpls_iptunnel"
  ];

  # MPTCP is built into the TCP stack, so a blocklist entry cannot reach it.
  boot.kernel.sysctl."net.mptcp.enabled" = 0;

  system.disableInstallerTools = lib.mkDefault true;
  system.switch.enable = lib.mkDefault false;

  users.mutableUsers = false;
  # Remove root password
  users.users.root.hashedPassword = lib.mkForce null;
  # Disable checking that at least the `root` user or a user in the `wheel` group can log in using a password or an SSH key
  users.allowNoPasswordLogin = lib.mkForce true;
}
