{ config, lib, pkgs, ... }:

# VM 303 — эталонная Canary-песочница (WBS B3-04).
# На узле прогоняются компиляторы сгенерированных патчей:
#   nix flake check, nixos-rebuild dry-build, sshd -t -f,
#   nft --check --json -f, ansible-playbook --syntax-check, augenrules --check.
{
  imports = [ ./hardening-baseline.nix ];

  # Компиляторы и линтеры, доступные агенту верификации.
  environment.systemPackages = with pkgs; [
    nftables
    openssh
    ansible
    ansible-lint
    nix
    jq
    python312
    python312Packages.pytest
    lynis
    openscap
  ];

  # nftables-политика на Canary применяется только после успешного
  # nft --check; до этого действует дефолтное состояние (пустой ruleset).
  networking.nftables.enable = true;

  # Isolated-пользователь для запуска проверяемых патчей.
  users.users.canary = {
    isNormalUser = true;
    description = "Canary verifier (unprivileged)";
    shell = pkgs.bash;
  };

  # Каталог для артефактов верификации.
  systemd.tmpfiles.rules = [
    "d /var/lib/b3-canary        0750 canary users -"
    "d /var/log/b3-canary        0750 canary users -"
  ];

  # Экспортёр метрик узла: Prometheus на VM 304 опрашивает порт 9100.
  services.prometheus.exporters.node = {
    enable = true;
    listenAddress = "10.30.1.33";
    port = 9100;
  };

  # Ограничение ресурсов, чтобы сбойный патч не уронил узел.
  systemd.slices.b3-canary = {
    description = "B3 Canary verification slice";
    sliceConfig = {
      MemoryMax = "2G";
      CPUQuota = "200%";
      TasksMax = 512;
    };
  };

  environment.etc."b3/canary-policy.md".text = ''
    # Canary verification policy (команда Б3)

    1. Патч считается валидным только при успехе ВСЕХ компиляторов:
       - nft --check --json -f <ruleset>
       - sshd -t -f <sshd_config>
       - augenrules --check
       - nix flake check
       - ansible-playbook --syntax-check
    2. Anti-Lockout Guard: до применения проверяется наличие
       `ct state established,related accept` и разрешающего правила
       для порта управления 22/tcp.
    3. При любом сбое патч помечается REJECTED и на целевой узел
       не передаётся.
  '';

  system.stateVersion = "25.11";
}
