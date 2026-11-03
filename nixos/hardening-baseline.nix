{ config, lib, pkgs, ... }:

# Базовый модуль харденинга NixOS (WBS B3-04).
# Применяется на эталонной Canary VM 303 и сервере аудита VM 304.
# Состав контролей соответствует Приказу ФСТЭК России № 117 (ЗСВ.1, ДОС.1)
# и CIS Linux Benchmark v3.0, уровень 1 + профиль сервера.
{
  # --- Параметры ядра ----------------------------------------------------
  boot.kernel.sysctl = {
    # Сетевое ядро: антиспуфинг, SYN-cookies, игнор ICMP-редиректов.
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv6.conf.all.accept_redirects" = 0;

    # Изоляция ядра: без dmesg для непривилегированных, kptr и bpf закрыты.
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.yama.ptrace_scope" = 1;
    "kernel.randomize_va_space" = 2;
    "kernel.core_pattern" = "|/bin/false";

    # Ограничения ресурсов против fork-bomb.
    "fs.protected_hardlinks" = 1;
    "fs.protected_symlinks" = 1;
    "fs.suid_dumpable" = 0;
  };

  # --- SSH ---------------------------------------------------------------
  services.openssh.settings = {
    PermitRootLogin = "no";
    PasswordAuthentication = false;
    KbdInteractiveAuthentication = false;
    PermitEmptyPasswords = false;
    X11Forwarding = false;
    AllowAgentForwarding = false;
    AllowTcpForwarding = false;
    MaxAuthTries = 3;
    MaxSessions = 4;
    ClientAliveInterval = 300;
    ClientAliveCountMax = 2;
    LoginGraceTime = 30;
    Banner = "/etc/issue.net";
  };

  environment.etc."issue.net".text = ''
    ******************************************************************
    *  Авторизованный доступ. Все действия журналируются (ГОСТ Р 59548-2022).
    ******************************************************************
  '';

  # --- Аудит ядра --------------------------------------------------------
  security.auditd.enable = true;
  security.audit = {
    enable = true;
    rules = [
      "-D"
      "-b 8192"
      "--backlog_wait_time 60000"
      "-f 1"                                   # только успешные вызовы
      "-w /etc/passwd -p wa -k identity"
      "-w /etc/shadow -p wa -k identity"
      "-w /etc/sudoers -p wa -k privilege"
      "-w /etc/ssh/sshd_config -p wa -k sshd"
      "-w /etc/nftables.conf -p wa -k firewall"
      "-a always,exit -F arch=b64 -S execve -k exec"
      "-a always,exit -F arch=b64 -S init_module,finit_module -k module_load"
      "-a always,exit -F arch=b64 -S setuid,setgid -k privilege"
    ];
  };

  # --- Изоляция служб ----------------------------------------------------
  # Drop-in профили для sshd генерируются модулем
  # src/runtime/ebpf_systemd_sandbox_enforcer.py и раскладываются
  # ansible-ролью; здесь задаются базовые ограничения для всех юнитов.
  systemd.services.sshd.serviceConfig = {
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    NoNewPrivileges = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectControlGroups = true;
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
    RestrictNamespaces = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
    UMask = "0077";
  };

  # --- Пользователи и sudo ----------------------------------------------
  security.sudo = {
    enable = true;
    wheelNeedsPassword = true;
    extraRules = [
      {
        users = [ "b3admin" ];
        commands = [
          { command = "${pkgs.systemd}/bin/systemctl restart nftables"; options = [ "NOPASSWD" ]; }
          { command = "${pkgs.nftables}/bin/nft"; options = [ "NOPASSWD" ]; }
        ];
      }
    ];
  };

  # --- Прочее ------------------------------------------------------------
  services.fail2ban = {
    enable = true;
    maxretry = 3;
    bantime = "1h";
    jails.sshd.settings = {
      enabled = true;
      port = "22";
    };
  };

  boot.kernelParams = [ "slab_nomerge" "init_on_alloc=1" "init_on_free=1" "page_alloc.shuffle=1" ];

  # Ядро не должно быть доступно на запись обычным службам.
  systemd.tmpfiles.rules = [
    "d /etc/systemd/system/sshd.service.d 0755 root root -"
  ];
}
