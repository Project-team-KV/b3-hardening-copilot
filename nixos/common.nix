{ config, lib, pkgs, ... }:

{
  imports = [ ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking = {
    useDHCP = false;
    defaultGateway = "10.30.1.1";
    nameservers = [ "10.30.1.1" "1.1.1.1" ];
    # Файрвол управляется nftables-политикой TopoGuard (модуль Роли 2).
    firewall.enable = false;
  };

  time.timeZone = "Asia/Omsk";
  i18n.defaultLocale = "ru_RU.UTF-8";

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    trusted-users = [ "root" "@wheel" ];
  };

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "prohibit-password";
      MaxAuthTries = 3;
      X11Forwarding = false;
    };
  };

  users.users.b3admin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    # Ключ добавляется при развёртывании стенда (scripts/provision_proxmox_b3.sh).
    openssh.authorizedKeys.keys = [ ];
  };

  environment.systemPackages = with pkgs; [
    git
    curl
    jq
    htop
    nftables
    tcpdump
  ];

  services.journald.extraConfig = ''
    SystemMaxUse=512M
    MaxRetentionSec=30day
  '';

  system.stateVersion = "25.11";
}
