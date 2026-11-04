"""Приёмочные и интеграционные тесты графового анализатора TopoGuard.

Проверяют пять инвариантов Zero-Trust Reachability из ТЗ команды Б3:
    INV-1 — нет маршрута из 0.0.0.0/0 к management-портам;
    INV-2 — проброс портов Docker не обходит хостовый input;
    INV-3 — нет висячих ссылок на пустые наборы адресов;
    INV-4 — согласованы MTU туннеля WireGuard и MSS Clamping;
    INV-5 — показатель защищённости периметра k31 рассчитан корректно.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from topoguard.iac_topoguard_ast import (
    MANAGEMENT_AND_INTERNAL_PORTS,
    AttackPathEdge,
    IaCTopoGuardAnalyzer,
    TopoGuardAuditReport,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def analyzer() -> IaCTopoGuardAnalyzer:
    """Новый экземпляр анализатора для каждого теста."""
    return IaCTopoGuardAnalyzer()


@pytest.fixture()
def insecure_nft() -> str:
    """Конфигурация уязвимого узла."""
    return (FIXTURES / "insecure" / "nftables.conf").read_text(encoding="utf-8")


@pytest.fixture()
def hardened_nft() -> str:
    """Конфигурация эталонного (захарденелого) узла."""
    return (FIXTURES / "hardened" / "nftables.conf").read_text(encoding="utf-8")


@pytest.fixture()
def insecure_wg() -> str:
    """Туннель WireGuard с MTU 1500."""
    return (FIXTURES / "insecure" / "wg0.conf").read_text(encoding="utf-8")


@pytest.fixture()
def hardened_wg() -> str:
    """Туннель WireGuard с MTU 1420."""
    return (FIXTURES / "hardened" / "wg0.conf").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Разбор AST
# ---------------------------------------------------------------------------
class TestNftablesParsing:
    """Юнит-тесты разбора nftables в нормализованный граф."""

    def test_returns_four_structures(self, analyzer, insecure_nft):
        declared, empty, policies, rules = analyzer.parse_nftables_ast(insecure_nft)
        assert isinstance(declared, list)
        assert isinstance(empty, list)
        assert isinstance(policies, dict)
        assert isinstance(rules, list)

    def test_empty_static_set_detected(self, analyzer, insecure_nft):
        """Набор без elements и без flags dynamic считается пустым."""
        declared, empty, _, _ = analyzer.parse_nftables_ast(insecure_nft)
        assert "allowed_admin" in empty
        assert "allowed_admin" not in declared

    def test_dynamic_set_is_not_empty(self, analyzer, hardened_nft):
        """Набор с flags dynamic валиден даже без elements."""
        declared, empty, _, _ = analyzer.parse_nftables_ast(hardened_nft)
        assert "ssh_rate" in declared
        assert "ssh_rate" not in empty

    def test_set_with_elements_is_not_empty(self, analyzer, hardened_nft):
        declared, empty, _, _ = analyzer.parse_nftables_ast(hardened_nft)
        assert "admin_bastion" in declared
        assert "admin_bastion" not in empty

    def test_chain_policies_extracted(self, analyzer, hardened_nft):
        _, _, policies, _ = analyzer.parse_nftables_ast(hardened_nft)
        assert policies["input"] == "drop"
        assert policies["forward"] == "drop"

    def test_rule_ports_normalized(self, analyzer, hardened_nft):
        _, _, _, rules = analyzer.parse_nftables_ast(hardened_nft)
        port_lists = {r.dst_ports for r in rules if r.dst_ports}
        assert (80, 443) in port_lists
        assert (5432, 6379, 9090, 9100) in port_lists

    def test_comments_do_not_break_parsing(self, analyzer):
        text = """
        table inet filter {
            chain input {
                type filter hook input priority filter; policy drop;
                tcp dport 22 accept  # ssh
            }
        }
        """
        _, _, policies, rules = analyzer.parse_nftables_ast(text)
        assert policies["input"] == "drop"
        assert len(rules) == 1
        assert rules[0].dst_ports == (22,)

    def test_check_line_is_ignored(self, analyzer):
        """Строка `tcp flags syn ... maxseg` не является правилом вердикта."""
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp flags syn tcp option maxseg size set rt mtu
            }
        }
        """
        _, _, _, rules = analyzer.parse_nftables_ast(text)
        assert rules == []


class TestIncludeExpansion:
    """Тесты разворачивания директив `include`."""

    def test_include_from_virtual_files(self, analyzer):
        main = 'include "/etc/nftables.d/*.nft"\n'
        virtual = {
            "/etc/nftables.d/10-hardening.nft": "tcp dport 22 accept",
        }
        expanded = analyzer.expand_includes(main, included_files=virtual)
        assert "tcp dport 22 accept" in expanded

    def test_unknown_include_removed(self, analyzer):
        expanded = analyzer.expand_includes('include "/nonexistent/*.nft"\n')
        assert "include" not in expanded


# ---------------------------------------------------------------------------
# INV-3: висячие ссылки
# ---------------------------------------------------------------------------
class TestDanglingSets:
    """INV-3: правило не должно ссылаться на пустой набор адресов."""

    def test_empty_set_reference_is_dangling(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        assert "allowed_admin" in report.dangling_sets

    def test_no_dangling_in_hardened(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft)
        assert report.dangling_sets == []

    def test_reference_to_undeclared_set_is_dangling(self, analyzer):
        text = """
        table inet filter {
            chain input {
                policy drop;
                ip saddr @ghost_set tcp dport 5432 accept
            }
        }
        """
        report = analyzer.analyze_topology(text)
        assert "ghost_set" in report.dangling_sets


# ---------------------------------------------------------------------------
# INV-1: достижимость management-портов
# ---------------------------------------------------------------------------
class TestReachability:
    """INV-1: management и внутренние СУБД недостижимы из 0.0.0.0/0."""

    def test_insecure_node_has_exposures(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        ports = {e.target_port for e in report.unrestricted_mgmt_exposures}
        assert {22, 5432, 9090} <= ports

    def test_ssh_exposure_is_high_severity(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        ssh = [e for e in report.unrestricted_mgmt_exposures if e.target_port == 22]
        assert ssh and all(e.severity == "HIGH" for e in ssh)

    def test_internal_db_exposure_is_critical(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        db = [e for e in report.unrestricted_mgmt_exposures if e.target_port == 5432]
        assert db and all(e.severity == "CRITICAL" for e in db)

    def test_hardened_node_has_no_exposures(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft)
        assert report.unrestricted_mgmt_exposures == []
        assert report.critical_paths == []

    def test_ssh_with_rate_limit_is_protected(self, analyzer):
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 meter ssh { ip saddr limit rate 3/minute } accept
            }
        }
        """
        report = analyzer.analyze_topology(text)
        assert all(e.target_port != 22 for e in report.unrestricted_mgmt_exposures)

    def test_ssh_from_bastion_only_is_protected(self, analyzer):
        text = """
        table inet filter {
            set bastion { type ipv4_addr; elements = { 10.30.1.0/24 } }
            chain input {
                policy drop;
                ip saddr @bastion tcp dport 22 accept
                ip saddr 10.30.1.0/24 tcp dport 22 accept
            }
        }
        """
        report = analyzer.analyze_topology(text)
        assert all(e.target_port != 22 for e in report.unrestricted_mgmt_exposures)

    def test_business_ports_require_drop_policy(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        assert report.k31_score < 1.0


# ---------------------------------------------------------------------------
# INV-2: обход через Docker
# ---------------------------------------------------------------------------
class TestDockerBypass:
    """INV-2: контейнерный проброс не должен обходить хостовый файрвол."""

    def test_bypass_detected_without_docker_user(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft, docker_enabled=True)
        assert report.docker_bypass_detected is True

    def test_no_bypass_without_docker(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft, docker_enabled=False)
        assert report.docker_bypass_detected is False

    def test_docker_user_chain_fixes_bypass(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft, docker_enabled=True)
        assert report.docker_bypass_detected is False

    def test_forward_drop_policy_fixes_bypass(self, analyzer):
        text = """
        table inet filter {
            chain input { policy drop; }
            chain forward { policy drop; }
        }
        """
        report = analyzer.analyze_topology(text, docker_enabled=True)
        assert report.docker_bypass_detected is False


# ---------------------------------------------------------------------------
# INV-4: WireGuard MTU и MSS Clamping
# ---------------------------------------------------------------------------
class TestWireGuard:
    """INV-4: MTU туннеля 1280..1420 и наличие MSS Clamping."""

    def test_mtu_1500_is_invalid(self, analyzer, insecure_nft, insecure_wg):
        report = analyzer.analyze_topology(insecure_nft, wireguard_conf=insecure_wg)
        assert report.wireguard_mtu_ok is False

    def test_mtu_1420_is_valid(self, analyzer, hardened_nft, hardened_wg):
        report = analyzer.analyze_topology(hardened_nft, wireguard_conf=hardened_wg)
        assert report.wireguard_mtu_ok is True

    def test_missing_mss_clamping_detected(self, analyzer, insecure_nft, insecure_wg):
        report = analyzer.analyze_topology(insecure_nft, wireguard_conf=insecure_wg)
        assert report.mss_clamping_ok is False

    def test_mss_clamping_present(self, analyzer, hardened_nft, hardened_wg):
        report = analyzer.analyze_topology(hardened_nft, wireguard_conf=hardened_wg)
        assert report.mss_clamping_ok is True

    def test_no_tunnel_skips_checks(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft, wireguard_conf="")
        assert report.wireguard_mtu_ok is True
        assert report.mss_clamping_ok is True


# ---------------------------------------------------------------------------
# INV-5: показатель k31 и сжатие маршрутов
# ---------------------------------------------------------------------------
class TestK31:
    """INV-5: расчёт показателя защищённости периметра."""

    def test_k31_is_one_for_hardened(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft)
        assert report.k31_score == pytest.approx(1.0)

    def test_k31_is_zero_for_insecure(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        assert report.k31_score == pytest.approx(0.0)

    def test_k31_partial_when_one_internal_port_exposed(self, analyzer):
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 meter ssh { ip saddr limit rate 3/minute } accept
                tcp dport { 80, 443 } accept
                ip saddr 0.0.0.0/0 tcp dport 5432 accept
            }
        }
        """
        report = analyzer.analyze_topology(text)
        assert 0.0 < report.k31_score < 1.0
        assert report.k31_score == pytest.approx(0.8)

    def test_noise_reduction_is_bounded(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        assert 0.0 <= report.noise_reduction_ratio <= 1.0

    def test_compressed_paths_unique(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        keys = [(e.via_chain, e.target_port) for e in report.compressed_attack_paths]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Гибридный iptables / ufw
# ---------------------------------------------------------------------------
class TestIptablesHybrid:
    """Разбор `iptables-save` для узлов с остатками netfilter-legacy."""

    def test_parses_policies_and_rules(self, analyzer):
        text = (FIXTURES / "insecure" / "rules.v4").read_text(encoding="utf-8")
        policies, rules = analyzer.parse_iptables_and_ufw(text)
        assert policies["input"] == "accept"
        assert any(22 in r.dst_ports for r in rules)
        assert any(5432 in r.dst_ports for r in rules)

    def test_hybrid_analysis_keeps_exposures(self, analyzer, hardened_nft):
        text = (FIXTURES / "insecure" / "rules.v4").read_text(encoding="utf-8")
        report = analyzer.analyze_topology(hardened_nft, iptables_text=text)
        ports = {e.target_port for e in report.unrestricted_mgmt_exposures}
        assert 22 in ports


# ---------------------------------------------------------------------------
# Вердикт, сериализация, аудит каталога
# ---------------------------------------------------------------------------
class TestReportContract:
    """Контракт отчёта: вердикт, сериализация, агрегированные поля."""

    def test_hardened_is_compliant(self, analyzer, hardened_nft, hardened_wg):
        report = analyzer.analyze_topology(
            hardened_nft, wireguard_conf=hardened_wg, docker_enabled=True
        )
        assert report.is_compliant is True
        assert report.failed_invariants == []

    def test_insecure_is_not_compliant(self, analyzer, insecure_nft, insecure_wg):
        report = analyzer.analyze_topology(
            insecure_nft, wireguard_conf=insecure_wg, docker_enabled=True
        )
        assert report.is_compliant is False
        assert len(report.failed_invariants) >= 3

    def test_to_dict_is_json_serializable(self, analyzer, insecure_nft):
        report = analyzer.analyze_topology(insecure_nft)
        payload = report.to_dict()
        encoded = json.dumps(payload, ensure_ascii=False)
        assert "k31_score" in encoded
        assert json.loads(encoded)["total_raw_rules"] == report.total_raw_rules

    def test_to_json_roundtrip(self, analyzer, hardened_nft):
        report = analyzer.analyze_topology(hardened_nft)
        restored = json.loads(report.to_json())
        assert restored["k31_score"] == report.k31_score
        assert restored["docker_bypass_detected"] is False

    def test_analyze_directory(self, analyzer):
        report = analyzer.analyze_directory(FIXTURES / "insecure")
        assert report.docker_bypass_detected is True
        assert report.total_raw_rules > 0
        assert report.docker_bypass_detected is True

    def test_analyze_directory_hardened(self, analyzer):
        report = analyzer.analyze_directory(FIXTURES / "hardened")
        assert report.is_compliant is True


def test_management_ports_match_spec():
    """Список management-портов соответствует ТЗ команды Б3."""
    assert MANAGEMENT_AND_INTERNAL_PORTS == frozenset({22, 5432, 6379, 9090, 9100})


def test_attack_path_route_format():
    """Текстовое представление маршрута атаки стабильно и читаемо."""
    edge = AttackPathEdge(
        source_zone="0.0.0.0/0 (Internet)",
        via_chain="input",
        target_port=5432,
        protocol="tcp",
        reason="test",
        severity="CRITICAL",
    )
    assert edge.as_route() == "0.0.0.0/0 (Internet) -> [input] -> tcp/5432 (CRITICAL)"


# ---------------------------------------------------------------------------
# Регрессионные тесты на найденные дефекты
# ---------------------------------------------------------------------------
class TestAnalyzerRegressions:
    """Дефекты, найденные при ревью: ложные «защищено» и потеря диапазонов."""

    def test_port_range_is_recorded(self, analyzer):
        """Диапазон 1000-2000 сохраняется, а не обрезается до 1000."""
        text = """
        table inet filter {
            chain input { policy drop; tcp dport 1000-2000 accept; }
        }
        """
        _, _, _, rules = analyzer.parse_nftables_ast(text)
        assert rules[0].dst_port_ranges == ((1000, 2000),)

    @pytest.mark.parametrize(
        "port, expected",
        [(999, False), (1000, True), (1500, True), (2000, True), (2001, False)],
    )
    def test_port_range_membership(self, analyzer, port, expected):
        """Порт внутри диапазона считается покрытым правилом."""
        text = """
        table inet filter {
            chain input { policy drop; tcp dport 1000-2000 accept; }
        }
        """
        _, _, _, rules = analyzer.parse_nftables_ast(text)
        assert rules[0].matches_port(port) is expected

    def test_port_range_detected_as_exposure(self, analyzer):
        """Открытый диапазон, накрывающий SSH, даёт маршрут атаки."""
        text = """
        table inet filter {
            chain input { policy accept; tcp dport 1000-2000 accept; }
        }
        """
        report = analyzer.analyze_topology(text)
        assert any(e.target_port == 22 for e in report.unrestricted_mgmt_exposures)

    def test_update_blocklist_is_not_rate_limit(self, analyzer):
        """``update @набор`` — запись в блок-лист, а не ограничение частоты."""
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 ct state new update @blocklist { ip saddr } accept
            }
        }
        """
        _, _, _, rules = analyzer.parse_nftables_ast(text)
        assert rules[0].has_rate_limit is False
        report = analyzer.analyze_topology(text)
        assert any(e.target_port == 22 for e in report.unrestricted_mgmt_exposures)

    def test_limit_rate_still_detected(self, analyzer):
        """Настоящий rate-limit по-прежнему распознаётся."""
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 update @lim { ip saddr limit rate 3/minute } accept
            }
        }
        """
        _, _, _, rules = analyzer.parse_nftables_ast(text)
        assert rules[0].has_rate_limit is True

    def test_commented_mss_rule_is_not_protection(self, analyzer):
        """Закомментированное правило MSS Clamping не считается защитой."""
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 accept
                # tcp flags syn tcp option maxseg size set rt mtu
            }
        }
        """
        report = analyzer.analyze_topology(text, wireguard_conf="MTU = 1420")
        assert report.mss_clamping_ok is False

    def test_active_mss_rule_is_protection(self, analyzer):
        """Активное правило MSS Clamping защитой считается."""
        text = """
        table inet filter {
            chain input {
                policy drop;
                tcp dport 22 accept
                tcp flags syn tcp option maxseg size set rt mtu
            }
        }
        """
        report = analyzer.analyze_topology(text, wireguard_conf="MTU = 1420")
        assert report.mss_clamping_ok is True
