{
  description = "Команда Б3 — Autonomous Linux & NixOS Hardening Copilot (стенд VM 301..304)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      lib = nixpkgs.lib;

      # Общий каркас узла стенда: статическая адресация в изолированном
      # мосте vmbr-b3 (10.30.1.0/24), SSH только по ключам.
      mkNode = { hostName, ipv4, extraModules ? [ ] }: lib.nixosSystem {
        inherit system;
        modules = [
          ./nixos/common.nix
          {
            networking.hostName = hostName;
            networking.interfaces.ens18.ipv4.addresses = [{
              address = ipv4;
              prefixLength = 24;
            }];
          }
        ] ++ extraModules;
      };
    in
    {
      nixosConfigurations = {
        # Ядро ИИ-копайлота: RTX 5080 (PCIe passthrough), vLLM, Qdrant.
        vm-301 = mkNode {
          hostName = "vm-301-copilot-gpu";
          ipv4 = "10.30.1.31";
          extraModules = [ ./nixos/vm-301-copilot-gpu.nix ];
        };

        # Целевой уязвимый Linux-узел с LAPP-стеком (Nginx + PostgreSQL).
        vm-302 = mkNode {
          hostName = "vm-302-vulnerable-target";
          ipv4 = "10.30.1.32";
          extraModules = [ ./nixos/vm-302-vulnerable-target.nix ];
        };

        # Эталонная Canary-песочница для компиляторной верификации патчей.
        vm-303 = mkNode {
          hostName = "vm-303-hardened-canary";
          ipv4 = "10.30.1.33";
          extraModules = [ ./nixos/vm-303-hardened-canary.nix ];
        };

        # Сервер аудита: PostgreSQL 16 (журнал ревизий), Prometheus, Grafana.
        vm-304 = mkNode {
          hostName = "vm-304-audit-server";
          ipv4 = "10.30.1.34";
          extraModules = [ ./nixos/vm-304-audit-server.nix ];
        };
      };

      # Воспроизводимое окружение разработки на PC-10.
      devShells.${system}.default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = with nixpkgs.legacyPackages.${system}; [
          python312
          python312Packages.pytest
          nftables
          openssh
          ansible
          postgresql_16
          git
          jq
        ];
        shellHook = ''
          export COPILOT_VLLM_URL="http://10.30.1.31:8000/v1"
          export COPILOT_QDRANT_URL="http://10.30.1.31:6333"
          export TARGET_SSH_HOST="root@10.30.1.32"
          export CANARY_SSH_HOST="root@10.30.1.33"
          echo "B3 devShell: VM 301..304 на 10.30.1.0/24"
        '';
      };

      formatter.${system} = nixpkgs.legacyPackages.${system}.nixpkgs-fmt;
    };
}
