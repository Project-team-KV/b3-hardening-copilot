{ config, lib, pkgs, ... }:

# VM 301 — ядро ИИ-копайлота (WBS B3-02, B3-03).
# RTX 5080 пробрасывается из Proxmox VE 9.2 через PCIe passthrough.
# На узле работают vLLM (OpenAI-совместимый API, порт 8000) и Qdrant (6333).
{
  # --- GPU ---------------------------------------------------------------
  hardware.enableRedistributableFirmware = true;

  services.xserver.videoDrivers = [ "nvidia" ];

  hardware.nvidia = {
    modesetting.enable = true;
    open = true;                    # открытый модуль обязателен для RTX 50xx
    nvidiaSettings = true;
    package = config.boot.kernelPackages.nvidiaPackages.latest;
  };

  hardware.graphics = {
    enable = true;
    enable32Bit = false;
  };

  # --- Контейнеры --------------------------------------------------------
  virtualisation.docker.enable = true;

  virtualisation.oci-containers.backend = "docker";
  virtualisation.oci-containers.containers.qdrant = {
    image = "qdrant/qdrant:latest";
    ports = [ "10.30.1.31:6333:6333" ];
    volumes = [ "/var/lib/qdrant:/qdrant/storage" ];
  };

  # --- Инференс vLLM -----------------------------------------------------
  # Qwen2.5-Coder-14B-Instruct-AWQ, поднимается из отдельного venv,
  # чтобы не блокировать пересборку системы весами модели (≈9 ГБ).
  systemd.services.vllm = {
    description = "vLLM OpenAI-compatible server (Qwen2.5-Coder-14B-AWQ)";
    after = [ "network-online.target" "docker.service" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "simple";
      Restart = "on-failure";
      RestartSec = 10;
      # Запускается пользователем b3admin из /opt/b3/venv.
      User = "b3admin";
      ExecStart = "/opt/b3/venv/bin/vllm serve Qwen/Qwen2.5-Coder-14B-Instruct-AWQ"
        + " --host 10.30.1.31 --port 8000"
        + " --quantization awq --max-model-len 16384"
        + " --gpu-memory-utilization 0.90";
      Environment = "HF_HOME=/var/lib/huggingface";
    };
    wantedBy = [ "multi-user.target" ];
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/huggingface 0750 b3admin users -"
    "d /var/lib/qdrant      0750 b3admin users -"
    "d /opt/b3             0755 root    root  -"
  ];

  # --- Мониторинг --------------------------------------------------------
  services.prometheus.exporters.node = {
    enable = true;
    listenAddress = "10.30.1.31";
    port = 9100;
  };

  networking.firewall.enable = false;

  environment.systemPackages = with pkgs; [
    python312
    python312Packages.pip
    cudaPackages.cuda_nvcc
    nvtopPackages.nvidia
    docker-compose
  ];
}
