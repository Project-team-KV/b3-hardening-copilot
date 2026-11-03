{ config, lib, pkgs, ... }:

# VM 302 — целевой уязвимый узел с LAPP-стеком (WBS B3-03).
#
# ВНИМАНИЕ: конфигурация намеренно ослаблена. Это полигон, на котором
# TopoGuard должен находить нарушения, а Canary-проверка — доказывать,
# что сгенерированный патч их устраняет. НЕ применять в продакшене.
{
  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    virtualHosts."target.b3.local" = {
      default = true;
      locations."/".return = "200 'B3 LAPP target node\\n'";
      locations."/healthz".return = "200 'ok'";
    };
  };

  services.postgresql = {
    enable = true;
    package = pkgs.postgresql_16;
    settings = {
      listen_addresses = "*";        # намеренно: СУБД слушает все интерфейсы
      port = 5432;
      password_encryption = "md5";   # намеренно устаревший метод
    };
    authentication = lib.mkForce ''
      host all all 0.0.0.0/0 md5
      local all all trust
    '';
  };

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = true;  # намеренно: парольный вход разрешён
      PermitRootLogin = "yes";        # намеренно: root-логин разрешён
      MaxAuthTries = 6;
    };
  };

  # Намеренно не включены: auditd, fail2ban, sysctl-харденинг.
  environment.systemPackages = with pkgs; [
    postgresql_16
    curl
    htop
  ];

  systemd.tmpfiles.rules = [
    "d /var/lib/b3-demo 0755 root root -"
  ];

  system.stateVersion = "25.11";
}
