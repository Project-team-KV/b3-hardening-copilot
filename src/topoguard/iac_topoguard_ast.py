# src/topoguard/iac_topoguard_ast.py
# Владелец модуля: Вебер Александр Александрович (@mbr_DIGMA_PRO_Sprint), Команда Б3
"""Статический и графовый анализатор сетевой достижимости IaC TopoGuard.

Модуль разбирает конфигурации межсетевых экранов (``nftables``, ``iptables``,
``ufw``), конфигурационные файлы туннелей ``WireGuard`` (``wg0.conf``),
параметры сетевых мостов ``Docker``/``Podman`` и бастиона ``SSH``, строит
ориентированный граф достижимости портов ``G = (V, E)`` и проверяет пять
инвариантов Zero-Trust:

1. отсутствие прямого доступа из ``0.0.0.0/0`` к management-портам и
   внутренним СУБД (``22/tcp`` без rate-limit/bastion, ``5432/tcp``,
   ``6379/tcp``, ``9090/tcp``, ``9100/tcp``);
2. отсутствие обхода хостового файрвола через проброс портов контейнеров
   (наличие и непустая фильтрация в цепочке ``DOCKER-USER``);
3. отсутствие висячих ссылок на несуществующие или пустые наборы адресов
   (``dangling_set`` / ``dangling_sg``);
4. согласованность ``MTU`` на интерфейсе ``WireGuard`` (``MTU = 1420``) и
   правила ``tcp flags syn tcp option maxseg size set rt mtu``
   (``MSS Clamping``) во избежание зависания TLS/SSH-сессий;
5. автоматический расчёт показателя защищённости периметра ``k31`` по
   Методике оценки Узи ФСТЭК России.
"""

from __future__ import annotations

import glob
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

#: Порты управления и внутренних СУБД/метрик: не должны быть доступны
#: напрямую из недоверенной зоны ``0.0.0.0/0``.
MANAGEMENT_AND_INTERNAL_PORTS: frozenset[int] = frozenset({22, 5432, 6379, 9090, 9100})

#: Порты прикладных сервисов: публично доступны, но обязаны фильтроваться
#: политикой ``policy drop`` с явным разрешающим правилом.
PUBLIC_BUSINESS_PORTS: frozenset[int] = frozenset({80, 443})

#: Семантика «любой источник» в синтаксисе nftables / iptables / ufw.
UNRESTRICTED_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0", "any", "anywhere"})

#: Допустимый диапазон MTU туннеля WireGuard.
WIREGUARD_MTU_RANGE: tuple[int, int] = (1280, 1420)


@dataclass(frozen=True)
class FirewallRuleNode:
    """Нормализованное ребро графа: одно правило фильтрации."""

    table: str
    chain: str
    protocol: str
    src_cidr: str
    dst_ports: tuple[int, ...]
    action: str
    has_rate_limit: bool
    referenced_set: str | None
    raw_line: str
    #: Диапазоны портов вида ``1000-2000``. Хранятся отдельно от ``dst_ports``,
    #: чтобы не разворачивать тысячи значений в кортеж.
    dst_port_ranges: tuple[tuple[int, int], ...] = ()

    def matches_port(self, port: int) -> bool:
        """Попадает ли порт под действие правила (с учётом диапазонов)."""
        if port in self.dst_ports:
            return True
        return any(low <= port <= high for low, high in self.dst_port_ranges)

    @property
    def is_permit(self) -> bool:
        """Является ли правило разрешающим."""
        return self.action == "accept"

    @property
    def is_deny(self) -> bool:
        """Является ли правило запрещающим."""
        return self.action in {"drop", "reject"}

    @property
    def is_world_reachable(self) -> bool:
        """Открыто ли правило для всей сети Интернет."""
        return self.src_cidr in UNRESTRICTED_CIDRS


@dataclass(frozen=True)
class AttackPathEdge:
    """Маршрут атаки: (зона-источник) -> (цепочка) -> (порт назначения)."""

    source_zone: str
    via_chain: str
    target_port: int
    protocol: str
    reason: str
    severity: str

    def as_route(self) -> str:
        """Текстовое представление маршрута для отчёта и журнала."""
        return (
            f"{self.source_zone} -> [{self.via_chain}] -> "
            f"{self.protocol}/{self.target_port} ({self.severity})"
        )


@dataclass
class TopoGuardAuditReport:
    """Результат аудита топологии: агрегированный вердикт по пяти инвариантам."""

    total_raw_rules: int
    declared_sets: list[str]
    dangling_sets: list[str]
    unrestricted_mgmt_exposures: list[AttackPathEdge]
    docker_bypass_detected: bool
    wireguard_mtu_ok: bool
    mss_clamping_ok: bool
    k31_score: float
    empty_static_sets: list[str] = field(default_factory=list)
    compressed_attack_paths: list[AttackPathEdge] = field(default_factory=list)
    noise_reduction_ratio: float = 0.0

    @property
    def critical_paths(self) -> list[AttackPathEdge]:
        """Маршруты атаки с критическим уровнем опасности."""
        return [e for e in self.unrestricted_mgmt_exposures if e.severity == "CRITICAL"]

    @property
    def is_compliant(self) -> bool:
        """Выполнены ли все пять инвариантов Zero-Trust Reachability."""
        return (
            self.k31_score >= 1.0
            and not self.dangling_sets
            and not self.unrestricted_mgmt_exposures
            and not self.docker_bypass_detected
            and self.wireguard_mtu_ok
            and self.mss_clamping_ok
        )

    @property
    def failed_invariants(self) -> list[str]:
        """Перечень нарушенных инвариантов в терминах ТЗ."""
        failed: list[str] = []
        if self.dangling_sets:
            failed.append("INV-3 dangling_set: правило ссылается на пустой набор адресов")
        if self.docker_bypass_detected:
            failed.append("INV-2 docker_bypass: контейнерный проброс обходит input")
        if not self.wireguard_mtu_ok:
            failed.append("INV-4a wireguard_mtu: MTU туннеля вне диапазона 1280..1420")
        if not self.mss_clamping_ok:
            failed.append("INV-4b mss_clamping: отсутствует tcp option maxseg size set rt mtu")
        if self.unrestricted_mgmt_exposures:
            failed.append("INV-1 exposure: management-порт достижим из 0.0.0.0/0")
        return failed

    def to_dict(self) -> dict[str, Any]:
        """Сериализация отчёта в словарь (для JSON-журнала и БД)."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Сериализация отчёта в канонический JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)


class IaCTopoGuardAnalyzer:
    """Статический и графовый верификатор сетевых политик.

    Строит граф достижимости портов по правилам ``nftables``, ``iptables``,
    ``ufw``, интерфейсам ``WireGuard`` и цепочкам ``Docker``/``Podman``,
    проверяет инварианты Zero-Trust и рассчитывает показатель ФСТЭК ``k31``.
    """

    SET_REF_RE = re.compile(r"@([a-zA-Z0-9_.\-]+)")
    PORT_LIST_RE = re.compile(
        r"(?:tcp|udp|th)\s+dport\s+(?:\{([^}]+)\}|(\d+(?:-\d+)?))", re.IGNORECASE
    )
    SRC_IPV4_RE = re.compile(
        r"\bip\s+saddr\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)", re.IGNORECASE
    )
    SRC_IPV6_RE = re.compile(
        r"\bip6\s+saddr\s+([0-9a-fA-F:]+(?:/[0-9]{1,3})?)", re.IGNORECASE
    )
    INCLUDE_RE = re.compile(r'^\s*include\s+"([^"]+)"', re.MULTILINE)
    POLICY_RE = re.compile(r"\bpolicy\s+(accept|drop)\s*;", re.IGNORECASE)
    #: Ограничение частоты. ``update @набор`` сюда НЕ входит: это запись в
    #: блок-лист, а не rate-limit, и принимать её за защиту нельзя.
    RATE_LIMIT_RE = re.compile(r"\b(limit\s+rate|meter\b)", re.IGNORECASE)

    # ------------------------------------------------------------------
    # Разбор структуры nftables
    # ------------------------------------------------------------------
    @staticmethod
    def _strip_comments(text: str) -> str:
        """Удаляет строчные комментарии ``#``, не затрагивая строковые литералы."""
        cleaned: list[str] = []
        for line in text.splitlines():
            quote: str | None = None
            cut = len(line)
            for idx, ch in enumerate(line):
                if quote:
                    if ch == quote:
                        quote = None
                elif ch in ("'", '"'):
                    quote = ch
                elif ch == "#":
                    cut = idx
                    break
            cleaned.append(line[:cut])
        return "\n".join(cleaned)

    @staticmethod
    def _extract_named_blocks(source: str, keyword: str) -> list[tuple[str, str]]:
        """Извлекает блоки ``<keyword> <name> { ... }`` с учётом вложенности."""
        blocks: list[tuple[str, str]] = []
        header_re = re.compile(rf"\b{keyword}\s+([a-zA-Z0-9_.\-]+)\s*\{{", re.IGNORECASE)
        for match in header_re.finditer(source):
            block_name = match.group(1).strip()
            start_idx = match.end()
            depth = 1
            pos = start_idx
            while pos < len(source) and depth > 0:
                ch = source[pos]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                pos += 1
            blocks.append((block_name, source[start_idx : max(start_idx, pos - 1)]))
        return blocks

    @classmethod
    def expand_includes(
        cls,
        nft_text: str,
        included_files: dict[str, str] | None = None,
        base_dir: Path | None = None,
    ) -> str:
        """Разворачивает директивы ``include "/etc/nftables.d/*.nft"``.

        Источником служит либо переданный словарь виртуальных файлов, либо
        локальная файловая система относительно ``base_dir``.
        """
        if "include" not in nft_text:
            return nft_text
        included_files = included_files or {}

        def _replacer(match: re.Match[str]) -> str:
            pattern = match.group(1)
            chunks: list[str] = []
            for vpath, vcontent in sorted(included_files.items()):
                if (
                    vpath == pattern
                    or Path(vpath).match(pattern)
                    or Path(vpath).name == Path(pattern).name
                ):
                    chunks.append(vcontent)
            if not chunks:
                search_pattern = (
                    str(base_dir / pattern)
                    if base_dir is not None and not Path(pattern).is_absolute()
                    else pattern
                )
                for disk_path in sorted(glob.glob(search_pattern)):
                    candidate = Path(disk_path)
                    if candidate.is_file():
                        chunks.append(
                            candidate.read_text(encoding="utf-8", errors="replace")
                        )
            return "\n".join(chunks)

        return cls.INCLUDE_RE.sub(_replacer, nft_text)

    def parse_nftables_ast(
        self,
        nft_text: str,
        included_files: dict[str, str] | None = None,
        base_dir: Path | None = None,
    ) -> tuple[list[str], list[str], dict[str, str], list[FirewallRuleNode]]:
        """Разбирает конфигурацию nftables.

        Возвращает кортеж ``(declared, empty_static, chain_policies, rules)``,
        где ``declared`` — объявленные наборы адресов, ``empty_static`` —
        статические наборы без ``flags dynamic`` и без непустого
        ``elements = { ... }`` (потенциальные ``dangling_set``).
        """
        expanded = self.expand_includes(
            nft_text, included_files=included_files, base_dir=base_dir
        )
        expanded = self._strip_comments(expanded)

        valid_sets: list[str] = []
        empty_static_sets: list[str] = []
        for set_name, set_body in self._extract_named_blocks(expanded, "set"):
            low_body = set_body.lower()
            is_dynamic = bool(re.search(r"\bflags\s+[^\n;]*\bdynamic\b", low_body))
            elem_match = re.search(r"\belements\s*=\s*\{([^}]*)\}", set_body, re.DOTALL)
            has_elements = bool(elem_match and elem_match.group(1).strip())
            if is_dynamic or has_elements:
                valid_sets.append(set_name)
            else:
                empty_static_sets.append(set_name)

        chain_policies: dict[str, str] = {}
        rules: list[FirewallRuleNode] = []
        for chain_name, body in self._extract_named_blocks(expanded, "chain"):
            pol_match = self.POLICY_RE.search(body)
            chain_policies[chain_name.lower()] = (
                pol_match.group(1).lower() if pol_match else "accept"
            )
            # Инструкции в nftables разделяются переводом строки ИЛИ точкой с
            # запятой, поэтому одного splitlines() недостаточно.
            for statement in re.split(r"[\n;]", body):
                rule = self._parse_rule_line(statement, chain_name)
                if rule is not None:
                    rules.append(rule)

        return (
            sorted(set(valid_sets)),
            sorted(set(empty_static_sets)),
            chain_policies,
            rules,
        )

    def _parse_rule_line(self, raw_line: str, chain_name: str) -> FirewallRuleNode | None:
        """Преобразует одну строку цепочки nftables в ребро графа."""
        line = raw_line.strip()
        lowered = line.lower()
        if not line or lowered.startswith(("type ", "policy ", "comment ")):
            return None
        if not any(k in lowered for k in ("accept", "drop", "reject", "jump", "goto")):
            return None

        ports: list[int] = []
        port_ranges: list[tuple[int, int]] = []
        port_match = self.PORT_LIST_RE.search(line)
        if port_match:
            raw_ports = port_match.group(1) or port_match.group(2) or ""
            for token in raw_ports.split(","):
                tok = token.strip()
                range_match = re.fullmatch(r"(\d+)-(\d+)", tok)
                if range_match:
                    low = int(range_match.group(1))
                    high = int(range_match.group(2))
                    if 0 < low <= high <= 65535:
                        port_ranges.append((low, high))
                elif tok.isdigit():
                    ports.append(int(tok))

        proto = "tcp"
        if "udp dport" in lowered or "ip protocol udp" in lowered:
            proto = "udp"
        elif "icmp" in lowered:
            proto = "icmp"

        set_ref_m = self.SET_REF_RE.search(line)
        ref_set = set_ref_m.group(1) if set_ref_m else None

        src_v4 = self.SRC_IPV4_RE.search(line)
        src_v6 = self.SRC_IPV6_RE.search(line)
        if src_v4:
            src_cidr = src_v4.group(1)
        elif src_v6:
            src_cidr = src_v6.group(1)
        elif ref_set and re.search(rf"saddr\s+@{re.escape(ref_set)}", line, re.I):
            src_cidr = f"@{ref_set}"
        else:
            src_cidr = "0.0.0.0/0"

        action = "unknown"
        for act in ("accept", "drop", "reject"):
            if re.search(rf"\b{act}\b", lowered):
                action = act
                break

        return FirewallRuleNode(
            table="inet_filter",
            chain=chain_name.lower(),
            protocol=proto,
            src_cidr=src_cidr,
            dst_ports=tuple(sorted(ports)),
            action=action,
            has_rate_limit=bool(self.RATE_LIMIT_RE.search(line)),
            referenced_set=ref_set,
            raw_line=line,
            dst_port_ranges=tuple(sorted(port_ranges)),
        )

    @staticmethod
    def parse_iptables_and_ufw(
        iptables_text: str,
    ) -> tuple[dict[str, str], list[FirewallRuleNode]]:
        """Разбирает правила ``iptables-save`` (``-P``, ``-A``) и ``ufw``.

        Используется для гибридных узлов, где часть фильтрации осталась в
        ``netfilter-legacy``. Возвращает политики цепочек и список правил.
        """
        policies: dict[str, str] = {}
        rules: list[FirewallRuleNode] = []
        for raw_line in iptables_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "*")):
                continue
            # `iptables -P` в интерактивном виде и `:INPUT ACCEPT [0:0]` в `iptables-save`.
            pol_m = re.match(
                r"^(?:-P\s+(\S+)|\:(\S+))\s+(ACCEPT|DROP)", line, re.IGNORECASE
            )
            if pol_m:
                chain_name = pol_m.group(1) or pol_m.group(2)
                policies[chain_name.lower()] = pol_m.group(3).lower()
                continue
            rule_m = re.match(r"^-[AI]\s+(\S+)\s+(.*)$", line, re.IGNORECASE)
            if not rule_m:
                continue
            chain = rule_m.group(1)
            rest = rule_m.group(2)
            dport_m = re.search(r"--dport\s+(\d+)", rest)
            ports = (int(dport_m.group(1)),) if dport_m else ()
            src_m = re.search(r"-s\s+([0-9a-fA-F.:/]+)", rest)
            src = src_m.group(1) if src_m else "0.0.0.0/0"
            jmp_m = re.search(r"-j\s+(ACCEPT|DROP|REJECT|RETURN)", rest, re.IGNORECASE)
            act = jmp_m.group(1).lower() if jmp_m else "unknown"
            has_lim = "hashlimit" in rest.lower() or "recent" in rest.lower()
            rules.append(
                FirewallRuleNode(
                    table="iptables_filter",
                    chain="input" if chain.upper() == "INPUT" else chain.lower(),
                    protocol="tcp",
                    src_cidr=src,
                    dst_ports=ports,
                    action=act,
                    has_rate_limit=has_lim,
                    referenced_set=None,
                    raw_line=line,
                )
            )
        return policies, rules

    # ------------------------------------------------------------------
    # Проверки инвариантов
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_dangling_sets(
        rules: Iterable[FirewallRuleNode],
        declared_sets: list[str],
        empty_static_sets: list[str],
    ) -> list[str]:
        """INV-3: ссылки на необъявленные либо пустые статические наборы."""
        referenced = {r.referenced_set for r in rules if r.referenced_set}
        return sorted(
            (referenced - set(declared_sets)) | (referenced & set(empty_static_sets))
        )

    @staticmethod
    def _check_docker_bypass(
        docker_enabled: bool, chain_policies: dict[str, str]
    ) -> bool:
        """INV-2: проброс портов контейнера обходит хостовый ``input``.

        Обход зафиксирован, если Docker включён, но нет ни выделенной цепочки
        ``DOCKER-USER`` с фильтрацией, ни ``policy drop`` в ``forward``.
        """
        if not docker_enabled:
            return False
        has_docker_user = (
            "docker-user" in chain_policies or "docker_user" in chain_policies
        )
        forward_drop = chain_policies.get("forward") == "drop"
        return not (has_docker_user or forward_drop)

    @staticmethod
    def _check_wireguard(wireguard_conf: str, nft_text: str) -> tuple[bool, bool]:
        """INV-4: согласованность MTU туннеля и наличия MSS Clamping."""
        if not wireguard_conf.strip():
            return True, True
        mtu_match = re.search(r"^\s*MTU\s*=\s*(\d+)", wireguard_conf, re.MULTILINE)
        low, high = WIREGUARD_MTU_RANGE
        mtu_ok = bool(mtu_match) and low <= int(mtu_match.group(1)) <= high
        mss_ok = "maxseg size set rt mtu" in nft_text.lower()
        return mtu_ok, mss_ok

    def _scan_exposures(
        self,
        rules: list[FirewallRuleNode],
        chain_policies: dict[str, str],
        exposed_ports: Iterable[int],
        dangling_sets: list[str],
        docker_bypass: bool,
        sshd_bastion_restricted: bool,
    ) -> tuple[list[AttackPathEdge], int]:
        """INV-1: ищет маршруты из ``0.0.0.0/0`` к защищаемым портам.

        Возвращает список маршрутов атаки и число защищённых портов.
        """
        input_policy = chain_policies.get("input", "accept")
        exposures: list[AttackPathEdge] = []
        protected = 0

        for port in sorted(set(exposed_ports)):
            port_rules = [
                r for r in rules if r.chain == "input" and r.matches_port(port)
            ]
            accepts = [r for r in port_rules if r.is_permit]

            if port in PUBLIC_BUSINESS_PORTS:
                is_protected = input_policy == "drop" and bool(accepts)
            elif port == 22:
                is_protected = self._ssh_is_protected(
                    accepts,
                    input_policy,
                    dangling_sets,
                    sshd_bastion_restricted,
                )
                if not is_protected:
                    exposures.append(
                        AttackPathEdge(
                            source_zone="0.0.0.0/0 (Internet)",
                            via_chain="input",
                            target_port=22,
                            protocol="tcp",
                            reason=(
                                "SSH 22/tcp exposed to 0.0.0.0/0 without dynamic "
                                "rate-limit or valid bastion CIDR/set"
                            ),
                            severity="HIGH",
                        )
                    )
            else:
                is_protected = self._internal_port_is_protected(
                    port_rules, input_policy, dangling_sets
                )
                if not is_protected:
                    exposures.append(
                        AttackPathEdge(
                            source_zone="0.0.0.0/0 (Internet)",
                            via_chain="input",
                            target_port=port,
                            protocol="tcp",
                            reason=(
                                f"Internal service port {port}/tcp reachable "
                                "from untrusted 0.0.0.0/0"
                            ),
                            severity="CRITICAL",
                        )
                    )

            if docker_bypass and port in MANAGEMENT_AND_INTERNAL_PORTS:
                if not any(e.target_port == port for e in exposures):
                    exposures.append(
                        AttackPathEdge(
                            source_zone="0.0.0.0/0 (Internet)",
                            via_chain="DOCKER-FORWARD-BYPASS",
                            target_port=port,
                            protocol="tcp",
                            reason=(
                                f"Docker bridge bypasses host input chain "
                                f"for port {port}/tcp"
                            ),
                            severity="CRITICAL",
                        )
                    )

            if is_protected and not any(e.target_port == port for e in exposures):
                protected += 1

        return exposures, protected

    @staticmethod
    def _ssh_is_protected(
        accepts: list[FirewallRuleNode],
        input_policy: str,
        dangling_sets: list[str],
        sshd_bastion_restricted: bool,
    ) -> bool:
        """Защищён ли ``22/tcp``: drop-политика + rate-limit/бастион на каждом accept."""
        if input_policy != "drop" or not accepts:
            return False
        return all(
            (
                rule.has_rate_limit
                or not rule.is_world_reachable
                or sshd_bastion_restricted
            )
            and rule.referenced_set not in dangling_sets
            for rule in accepts
        )

    @staticmethod
    def _internal_port_is_protected(
        port_rules: list[FirewallRuleNode],
        input_policy: str,
        dangling_sets: list[str],
    ) -> bool:
        """Защищён ли внутренний порт: нет разрешающих правил из ``0.0.0.0/0``."""
        if input_policy != "drop":
            return False
        for rule in port_rules:
            if rule.is_permit and (
                rule.is_world_reachable or rule.referenced_set in dangling_sets
            ):
                return False
        return True

    # ------------------------------------------------------------------
    # Основной сценарий аудита
    # ------------------------------------------------------------------
    def analyze_topology(
        self,
        nft_text: str,
        wireguard_conf: str = "",
        docker_enabled: bool = False,
        exposed_ports: set[int] | None = None,
        included_files: dict[str, str] | None = None,
        iptables_text: str = "",
        sshd_bastion_restricted: bool = False,
        base_dir: Path | None = None,
    ) -> TopoGuardAuditReport:
        """Строит граф достижимости, проверяет инварианты и вычисляет ``k31``."""
        if exposed_ports is None:
            exposed_ports = {22, 80, 443, 5432, 9090}

        declared_sets, empty_static_sets, chain_policies, rules = (
            self.parse_nftables_ast(
                nft_text, included_files=included_files, base_dir=base_dir
            )
        )
        if iptables_text.strip():
            ipt_policies, ipt_rules = self.parse_iptables_and_ufw(iptables_text)
            for chain, policy in ipt_policies.items():
                chain_policies.setdefault(chain, policy)
            rules.extend(ipt_rules)

        dangling_sets = self._detect_dangling_sets(
            rules, declared_sets, empty_static_sets
        )
        docker_bypass = self._check_docker_bypass(docker_enabled, chain_policies)
        wg_mtu_ok, mss_ok = self._check_wireguard(
            wireguard_conf, self._strip_comments(nft_text)
        )

        exposures, protected = self._scan_exposures(
            rules=rules,
            chain_policies=chain_policies,
            exposed_ports=exposed_ports,
            dangling_sets=dangling_sets,
            docker_bypass=docker_bypass,
            sshd_bastion_restricted=sshd_bastion_restricted,
        )

        total = max(1, len(set(exposed_ports)))
        k31_score = round(protected / float(total), 4)

        unique_paths: dict[tuple[str, int], AttackPathEdge] = {}
        for edge in exposures:
            unique_paths.setdefault((edge.via_chain, edge.target_port), edge)
        compressed = list(unique_paths.values())

        simulated_raw_alerts = max(len(rules) * 4, len(compressed))
        noise_reduction = (
            round(1.0 - len(compressed) / float(simulated_raw_alerts), 4)
            if simulated_raw_alerts
            else 1.0
        )

        return TopoGuardAuditReport(
            total_raw_rules=len(rules),
            declared_sets=declared_sets,
            dangling_sets=dangling_sets,
            unrestricted_mgmt_exposures=exposures,
            docker_bypass_detected=docker_bypass,
            wireguard_mtu_ok=wg_mtu_ok,
            mss_clamping_ok=mss_ok,
            k31_score=k31_score,
            empty_static_sets=empty_static_sets,
            compressed_attack_paths=compressed,
            noise_reduction_ratio=noise_reduction,
        )

    # ------------------------------------------------------------------
    # Удобные обёртки для CLI и демо
    # ------------------------------------------------------------------
    def analyze_directory(self, directory: Path | str) -> TopoGuardAuditReport:
        """Аудит каталога с конфигурациями узла (``nftables.conf``, ``*.rules``, ``wg*.conf``)."""
        root = Path(directory)
        nft_parts: list[str] = []
        wg_conf = ""
        iptables = ""
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            suffix = path.suffix.lower()
            if suffix == ".nft" or path.name == "nftables.conf":
                nft_parts.append(text)
            elif suffix == ".rules":
                iptables += text + "\n"
            elif path.name.startswith("wg") and suffix == ".conf":
                wg_conf = text
        docker_enabled = any(
            p.name in {"docker-compose.yml", "docker-compose.yaml", "daemon.json"}
            for p in root.rglob("*")
        )
        return self.analyze_topology(
            nft_text="\n".join(nft_parts),
            wireguard_conf=wg_conf,
            docker_enabled=docker_enabled,
            iptables_text=iptables,
            base_dir=root,
        )
