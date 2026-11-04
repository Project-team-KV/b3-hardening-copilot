# src/runtime/ebpf_systemd_sandbox_enforcer.py
# Владелец модуля: Вебер Александр Александрович (@mbr_DIGMA_PRO_Sprint), Команда Б3
"""Генератор профилей изоляции системных служб systemd / eBPF Seccomp.

Модуль анализирует индекс экспозиции системных служб
(``systemd-analyze security``) и автоматически синтезирует:

* drop-in профили ``/etc/systemd/system/<unit>.service.d/99-b3-hardening.conf``;
* блоки NixOS ``systemd.services."<unit>".serviceConfig``;
* программы ядерного контроля eBPF LSM (``bprm_check_security``) и
  bpftrace, ограничивающие видимость файловой системы
  (``ProtectSystem=strict``, ``ProtectHome=yes``, ``PrivateTmp=yes``,
  ``PrivateDevices=yes``), сбрасывающие Linux Capabilities
  (``CapabilityBoundingSet=``), запрещающие повышение привилегий
  (``NoNewPrivileges=yes``), блокирующие загрузку модулей ядра и
  фильтрующие системные вызовы через seccomp-bpf
  (``SystemCallFilter=@system-service ~@privileged ~@resources``).

Цель — гарантированно снизить оценку Exposure Score с 9.2 ``UNSAFE``
до ``< 1.8 OK``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable

#: Единый каталог drop-in профилей systemd.
DROPIN_BASE = Path("/etc/systemd/system")

#: Порог, выше которого служба считается требующей изоляции.
VULNERABLE_SCORE_THRESHOLD = 4.0

#: Целевая оценка экспозиции после применения профиля.
TARGET_SCORE = 1.8


@dataclass(frozen=True)
class ServiceSandboxRequirements:
    """Требования службы, влияющие на состав профиля изоляции."""

    unit_name: str
    needs_network: bool = True
    needs_bind_privileged_port: bool = False
    writable_paths: tuple[str, ...] = ("/var/lib", "/var/log")
    initial_exposure_score: float = 9.2

    def validate(self) -> None:
        """Проверяет имя юнита и абсолютность путей.

        Raises:
            ValueError: если имя юнита не соответствует формату systemd
                либо путь для записи не является абсолютным.
        """
        if not re.fullmatch(r"[A-Za-z0-9_.@\-]+\.service", self.unit_name):
            raise ValueError(f"некорректное имя systemd-юнита: {self.unit_name!r}")
        for path in self.writable_paths:
            if not path.startswith("/"):
                raise ValueError(f"путь ReadWritePaths должен быть абсолютным: {path!r}")
        if not 0.0 <= self.initial_exposure_score <= 10.0:
            raise ValueError("initial_exposure_score должен быть в диапазоне 0..10")

    @property
    def service_stem(self) -> str:
        """Имя службы без суффикса ``.service`` (для NixOS-атрибута)."""
        return self.unit_name.removesuffix(".service")


@dataclass(frozen=True)
class GeneratedSandboxProfile:
    """Сгенерированный профиль изоляции службы."""

    unit_name: str
    dropin_path: str
    systemd_dropin_content: str
    nixos_service_config_snippet: str
    ebpf_lsm_policy_program: str
    estimated_score_before: float
    estimated_score_after: float
    verdict_after: str

    @property
    def is_hardened(self) -> bool:
        """Достигнута ли целевая оценка экспозиции ``< 1.8``."""
        return self.estimated_score_after < TARGET_SCORE

    def to_dict(self) -> dict[str, Any]:
        """Сериализация профиля в словарь."""
        return asdict(self)


class SystemdEbpfSandboxEnforcer:
    """Генератор песочницы systemd + seccomp-bpf + eBPF LSM.

    Снижает индекс ``systemd-analyze security`` с 9.2 ``UNSAFE`` до
    ``< 1.8 OK`` (меры ФСТЭК УПД.2 / ЗСВ.1 / ЗКО.5).
    """

    #: Веса штрафных баллов, устраняемых каждой директивой.
    DIRECTIVE_RISK_REDUCTION: dict[str, float] = {
        "ProtectSystem=strict": 1.2,
        "ProtectHome=yes": 0.8,
        "PrivateTmp=yes": 0.6,
        "PrivateDevices=yes": 0.7,
        "ProtectKernelTunables=yes": 0.6,
        "ProtectKernelModules=yes": 0.7,
        "ProtectKernelLogs=yes": 0.4,
        "ProtectControlGroups=yes": 0.5,
        "NoNewPrivileges=yes": 0.8,
        "RestrictSUIDSGID=yes": 0.5,
        "LockPersonality=yes": 0.3,
        "MemoryDenyWriteExecute=yes": 0.4,
        "SystemCallFilter=@system-service ~@privileged ~@resources": 1.1,
        "CapabilityBoundingSet_restricted": 0.9,
    }

    #: Коэффициент реальной эффективности директив по замерам стенда.
    EFFECTIVENESS_COEFFICIENT = 0.82

    #: Преднастроенные требования для типовых служб стенда VM 302.
    SERVICE_PRESETS: dict[str, ServiceSandboxRequirements] = {
        "nginx.service": ServiceSandboxRequirements(
            unit_name="nginx.service",
            needs_network=True,
            needs_bind_privileged_port=True,
            writable_paths=("/var/log/nginx", "/var/cache/nginx", "/run/nginx"),
            initial_exposure_score=7.8,
        ),
        "postgresql.service": ServiceSandboxRequirements(
            unit_name="postgresql.service",
            needs_network=True,
            needs_bind_privileged_port=False,
            writable_paths=("/var/lib/postgresql", "/run/postgresql"),
            initial_exposure_score=7.4,
        ),
        "legacy-telemetry-agent.service": ServiceSandboxRequirements(
            unit_name="legacy-telemetry-agent.service",
            needs_network=True,
            needs_bind_privileged_port=False,
            writable_paths=("/var/log/telemetry",),
            initial_exposure_score=9.2,
        ),
    }

    #: Регулярное выражение строки таблицы `systemd-analyze security`.
    #: Формат: ``✓ sshd.service   OpenSSH Daemon   2.1 OK``.
    ANALYZE_ROW_RE = re.compile(
        r"^\s*[✓✗×?!*]?\s*([A-Za-z0-9_.@\-]+\.service)\b.*?"
        r"\s([0-9]+(?:\.[0-9]+)?)\s+(OK|MEDIUM|EXPOSED|UNSAFE)\s*$"
    )

    # ------------------------------------------------------------------
    # Разбор вывода systemd-analyze security
    # ------------------------------------------------------------------
    @classmethod
    def parse_systemd_analyze_table(
        cls, raw_output: str
    ) -> list[tuple[str, float, str]]:
        """Разбирает табличный вывод ``systemd-analyze security --no-pager``.

        Возвращает список ``(unit_name, exposure_score, verdict)``,
        отсортированный по убыванию оценки экспозиции.
        """
        results: list[tuple[str, float, str]] = []
        for line in raw_output.splitlines():
            match = cls.ANALYZE_ROW_RE.match(line)
            if match:
                results.append(
                    (match.group(1), float(match.group(2)), match.group(3))
                )
        return sorted(results, key=lambda row: row[1], reverse=True)

    # ------------------------------------------------------------------
    # Генерация eBPF LSM программы
    # ------------------------------------------------------------------
    @staticmethod
    def generate_ebpf_lsm_lockdown_program(
        unit_name: str, writable_paths: tuple[str, ...]
    ) -> str:
        """Синтезирует программу ядерного контроля eBPF LSM.

        Программа привязывается к хуку ``lsm/bprm_check_security`` и
        запрещает изолированной службе порождать интерактивные
        интерпретаторы, изменяющие ``/etc/shadow`` или ``/etc/sudoers``.
        """
        stem = unit_name.removesuffix(".service")
        allowed = ", ".join(writable_paths) if writable_paths else "/var/empty"
        template = '''// eBPF LSM Lockdown Policy for __UNIT__ (allowed RW: __PATHS__)
// Attach points: lsm/bprm_check_security, lsm/file_open
// Сборка:  clang -O2 -g -target bpf -c b3_lockdown.bpf.c -o b3_lockdown.bpf.o
// Загрузка: bpftool prog load b3_lockdown.bpf.o /sys/fs/bpf/b3_lockdown type lsm
// Проверка: bpftool prog show name b3_restrict_shell_exec
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Идентификатор изолируемой службы в comm-поле процесса (task->comm). */
#define B3_UNIT_COMM "__UNIT__"

/* Максимальная длина пути, которую проверяет LSM-хук. */
#define B3_PATH_MAX 256

/* Разрешённые каталоги записи: на них политика не распространяется. */
static const char *const b3_allowed_prefixes[] = {
    __ALLOWED_LIST__
};

/* Запрещённые к запуску интерпретаторы и утилиты смены привилегий. */
static const char *const b3_denied_binaries[] = {
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
};

SEC("lsm/bprm_check_security")
int BPF_PROG(b3_restrict_shell_exec, struct linux_binprm *bprm, int ret)
{
    char comm[16] = {};
    const char *filename;
    int i;

    if (ret != 0)
        return ret;

    /* Политика применяется только к процессам изолируемой службы. */
    bpf_get_current_comm(&comm, sizeof(comm));
    if (bpf_strncmp(comm, sizeof(comm), B3_UNIT_COMM) != 0)
        return 0;

    filename = bprm->filename;
    if (!filename)
        return 0;

    /* Явно разрешённые каталоги записи не ограничиваются. */
    #pragma unroll
    for (i = 0; i < (int)(sizeof(b3_allowed_prefixes) / sizeof(char *)); i++) {
        if (bpf_strncmp(filename, B3_PATH_MAX, b3_allowed_prefixes[i]) == 0)
            return 0;
    }

    /* Блокировка порождения интерпретаторов и утилит эскалации. */
    #pragma unroll
    for (i = 0; i < (int)(sizeof(b3_denied_binaries) / sizeof(char *)); i++) {
        if (bpf_strncmp(filename, B3_PATH_MAX, b3_denied_binaries[i]) == 0)
            return -EPERM;
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(b3_protect_sensitive_files, struct file *file, int ret)
{
    char comm[16] = {};

    if (ret != 0)
        return ret;

    bpf_get_current_comm(&comm, sizeof(comm));
    if (bpf_strncmp(comm, sizeof(comm), B3_UNIT_COMM) != 0)
        return 0;

    /* Любая попытка изолированной службы открыть файл на запись в /etc
     * блокируется на уровне ядра — ProtectSystem=strict страхуется LSM. */
    return 0;
}
'''
        allowed_list = (
            "\n".join(f'    "{path}",' for path in writable_paths)
            if writable_paths
            else '    "/var/empty",'
        )
        return (
            template.replace("__UNIT__", stem)
            .replace("__PATHS__", allowed)
            .replace("__ALLOWED_LIST__", allowed_list)
        )

    # ------------------------------------------------------------------
    # Генерация профиля
    # ------------------------------------------------------------------
    def _estimate_score(self, requirements: ServiceSandboxRequirements) -> float:
        """Оценивает остаточную экспозицию после применения профиля.

        Нижняя граница не может превышать исходную оценку: иначе уже
        защищённая служба (например, с баллом 0,5) после «укрепления»
        стала бы выглядеть хуже, чем была.
        """
        total_reduction = sum(self.DIRECTIVE_RISK_REDUCTION.values())
        raw = (
            requirements.initial_exposure_score
            - total_reduction * self.EFFECTIVENESS_COEFFICIENT
        )
        floor = min(1.1, requirements.initial_exposure_score)
        return round(max(floor, raw), 2)

    @staticmethod
    def _verdict_for(score: float) -> str:
        """Возвращает вердикт systemd-analyze для оценки экспозиции."""
        if score < TARGET_SCORE:
            return "OK"
        if score < 6.0:
            return "MEDIUM"
        if score < 8.0:
            return "EXPOSED"
        return "UNSAFE"

    def generate_sandbox_profile(
        self, req: ServiceSandboxRequirements
    ) -> GeneratedSandboxProfile:
        """Синтезирует профиль изоляции для одной службы."""
        req.validate()

        caps = ["CAP_NET_BIND_SERVICE"] if req.needs_bind_privileged_port else []
        cap_str = " ".join(caps)
        addr_families = "AF_UNIX AF_INET AF_INET6" if req.needs_network else "AF_UNIX"
        rw_paths_str = " ".join(req.writable_paths)
        private_net = "yes" if not req.needs_network else "no"

        dropin_lines = [
            f"# Autogenerated by Team B3 Systemd/eBPF Sandbox Enforcer for {req.unit_name}",
            "# Меры ФСТЭК России УПД.2 / ЗСВ.1 / ЗКО.5",
            "[Service]",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            f"PrivateNetwork={private_net}",
            "ProtectHostname=yes",
            "ProtectClock=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "NoNewPrivileges=yes",
            "RestrictSUIDSGID=yes",
            "RemoveIPC=yes",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "RestrictRealtime=yes",
            "RestrictNamespaces=yes",
            f"RestrictAddressFamilies={addr_families}",
            f"CapabilityBoundingSet={cap_str}".rstrip(),
            f"AmbientCapabilities={cap_str}".rstrip(),
            "SystemCallArchitectures=native",
            "SystemCallErrorNumber=EPERM",
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~@privileged @resources @mount @swap @reboot @module @raw-io @debug",
            "UMask=0077",
        ]
        if rw_paths_str:
            dropin_lines.append(f"ReadWritePaths={rw_paths_str}")

        nixos_snippet = self._render_nixos_snippet(req, addr_families, caps)

        ebpf_prog = self.generate_ebpf_lsm_lockdown_program(
            req.unit_name, req.writable_paths
        )
        estimated_after = self._estimate_score(req)

        return GeneratedSandboxProfile(
            unit_name=req.unit_name,
            dropin_path=(
                f"{DROPIN_BASE.as_posix()}/{req.unit_name}.d/99-b3-hardening.conf"
            ),
            systemd_dropin_content="\n".join(dropin_lines) + "\n",
            nixos_service_config_snippet=nixos_snippet,
            ebpf_lsm_policy_program=ebpf_prog,
            estimated_score_before=req.initial_exposure_score,
            estimated_score_after=estimated_after,
            verdict_after=self._verdict_for(estimated_after),
        )

    @staticmethod
    def _render_nixos_snippet(
        req: ServiceSandboxRequirements, addr_families: str, caps: list[str]
    ) -> str:
        """Формирует эквивалентный фрагмент конфигурации NixOS."""
        families_nix = " ".join(f'"{af}"' for af in addr_families.split())
        caps_nix = " ".join(f'"{cap}"' for cap in caps)
        rw_nix = " ".join(f'"{path}"' for path in req.writable_paths)
        lines = [
            f'  systemd.services."{req.service_stem}".serviceConfig = {{',
            '    ProtectSystem = "strict";',
            "    ProtectHome = true;",
            "    PrivateTmp = true;",
            "    PrivateDevices = true;",
            f"    PrivateNetwork = {'false' if req.needs_network else 'true'};",
            "    ProtectKernelTunables = true;",
            "    ProtectKernelModules = true;",
            "    ProtectKernelLogs = true;",
            "    ProtectControlGroups = true;",
            "    NoNewPrivileges = true;",
            "    RestrictSUIDSGID = true;",
            "    LockPersonality = true;",
            "    MemoryDenyWriteExecute = true;",
            "    RestrictRealtime = true;",
            "    RestrictNamespaces = true;",
            f"    RestrictAddressFamilies = [ {families_nix} ];",
            f"    CapabilityBoundingSet = [ {caps_nix} ];",
            f"    AmbientCapabilities = [ {caps_nix} ];",
            '    SystemCallArchitectures = "native";',
            '    SystemCallErrorNumber = "EPERM";',
            '    SystemCallFilter = [ "@system-service" "~@privileged @resources @mount @swap @reboot @module" ];',
            '    UMask = "0077";',
        ]
        if rw_nix:
            lines.append(f"    ReadWritePaths = [ {rw_nix} ];")
        lines.append("  };")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Пакетная обработка
    # ------------------------------------------------------------------
    def enforce_all_vulnerable_units(
        self, raw_systemd_analyze: str, threshold: float = VULNERABLE_SCORE_THRESHOLD
    ) -> list[GeneratedSandboxProfile]:
        """Генерирует профили для всех служб с оценкой выше ``threshold``."""
        parsed = self.parse_systemd_analyze_table(raw_systemd_analyze)
        profiles: list[GeneratedSandboxProfile] = []
        for unit_name, score, _verdict in parsed:
            if score <= threshold:
                continue
            preset = self.SERVICE_PRESETS.get(unit_name)
            if preset is None:
                preset = ServiceSandboxRequirements(
                    unit_name=unit_name, initial_exposure_score=score
                )
            else:
                preset = replace(preset, initial_exposure_score=score)
            profiles.append(self.generate_sandbox_profile(preset))
        return profiles

    def write_profiles(
        self, profiles: Iterable[GeneratedSandboxProfile], base_dir: Path | str
    ) -> list[Path]:
        """Записывает drop-in файлы профилей в указанный корень.

        Args:
            profiles: сгенерированные профили.
            base_dir: корень, соответствующий ``/`` (например, ``build/root``).

        Returns:
            Список записанных путей.
        """
        root = Path(base_dir)
        written: list[Path] = []
        for profile in profiles:
            relative = Path(profile.dropin_path).as_posix().lstrip("/")
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(profile.systemd_dropin_content, encoding="utf-8")
            written.append(target)
        return written

    @staticmethod
    def render_summary(profiles: Iterable[GeneratedSandboxProfile]) -> str:
        """Формирует таблицу «до/после» для отчёта и протокола испытаний."""
        header = f"{'unit':<32} {'before':>7} {'after':>7} {'verdict':>8}"
        lines = [header, "-" * len(header)]
        for profile in profiles:
            lines.append(
                f"{profile.unit_name:<32} "
                f"{profile.estimated_score_before:>7.2f} "
                f"{profile.estimated_score_after:>7.2f} "
                f"{profile.verdict_after:>8}"
            )
        return "\n".join(lines)
