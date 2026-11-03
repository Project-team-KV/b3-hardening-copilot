{ config, lib, pkgs, ... }:

# VM 304 — сервер аудита (WBS B3-04, B3-18).
# Хранит неизменяемый журнал ревизий (migrations/001_hardening_ledger.sql),
# собирает метрики Prometheus и визуализирует их в Grafana.
{
  imports = [ ./hardening-baseline.nix ];

  services.postgresql = {
    enable = true;
    package = pkgs.postgresql_16;
    settings = {
      listen_addresses = "10.30.1.34";
      port = 5432;
      # Журнал ревизий критичен: полная синхронизация на диск.
      fsync = "on";
      synchronous_commit = "on";
      full_page_writes = "on";
    };
    ensureDatabases = [ "hardening" ];
    ensureUsers = [
      {
        name = "secops";
        ensureDBOwnership = true;
      }
    ];
    # Схема применяется миграцией при первом развёртывании:
    #   psql -U secops -d hardening -f migrations/001_hardening_ledger.sql
  };

  services.prometheus = {
    enable = true;
    listenAddress = "10.30.1.34";
    port = 9090;
    globalConfig.scrape_interval = "15s";
    scrapeConfigs = [
      {
        job_name = "node";
        static_configs = [
          { targets = [ "10.30.1.31:9100" "10.30.1.32:9100" "10.30.1.33:9100" "10.30.1.34:9100" ]; }
        ];
      }
      {
        # Метрики сервера инференса vLLM (порт 8000 на VM 301).
        # Сам TopoGuard — консольная программа без HTTP-интерфейса и своих
        # метрик не отдаёт, поэтому задача названа по фактическому источнику.
        job_name = "vllm";
        metrics_path = "/metrics";
        static_configs = [ { targets = [ "10.30.1.31:8000" ]; } ];
      }
    ];
  };

  services.grafana = {
    enable = true;
    settings = {
      server = {
        http_addr = "10.30.1.34";
        http_port = 3000;
      };
      analytics.reporting_enabled = false;
    };
    provision = {
      enable = true;
      datasources.settings.datasources = [
        {
          name = "Prometheus";
          type = "prometheus";
          access = "proxy";
          url = "http://127.0.0.1:9090";
        }
      ];
    };
  };

  # Резервное копирование журнала ревизий.
  services.postgresqlBackup = {
    enable = true;
    databases = [ "hardening" ];
    startAt = "*-*-* 03:30:00";
  };

  environment.systemPackages = with pkgs; [
    postgresql_16
    prometheus
    grafana
    jq
  ];

  systemd.tmpfiles.rules = [
    "d /var/backup/postgresql 0700 postgres postgres -"
  ];

  # Экспортёр метрик узла: Prometheus опрашивает порт 9100 на всех машинах стенда.
  services.prometheus.exporters.node = {
    enable = true;
    listenAddress = "10.30.1.34";
    port = 9100;
  };

  system.stateVersion = "25.11";
}
