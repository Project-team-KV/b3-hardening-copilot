"""Тесты генератора эталонного nftables.conf и компиляторного прувера.

Проверяют:
    * структурную корректность синтезируемого ruleset;
    * round-trip: сгенерированный файрвол проходит аудит TopoGuard с k31 = 1.0;
    * работу переключателей (MSS Clamping, egress-фильтр, honeytrap);
    * валидацию входной спецификации.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from topoguard.iac_topoguard_ast import IaCTopoGuardAnalyzer
from topoguard.nftables_generator_and_prover import (
    NftablesGeneratorAndProver,
    NftablesPolicySpec,
    NftablesProofResult,
)


@pytest.fixture()
def prover() -> NftablesGeneratorAndProver:
    """Новый генератор-прувер для каждого теста."""
    return NftablesGeneratorAndProver()


@pytest.fixture()
def spec() -> NftablesPolicySpec:
    """Эталонная спецификация по умолчанию."""
    return NftablesPolicySpec()


@pytest.fixture()
def ruleset(prover, spec) -> str:
    """Сгенерированный эталонный ruleset."""
    return prover.generate_ruleset(spec)


# ---------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------
class TestGeneration:
    """Структура и содержимое сгенерированного ruleset."""

    def test_starts_with_nft_shebang(self, ruleset):
        assert ruleset.startswith("#!/usr/sbin/nft -f")

    def test_contains_all_required_chains(self, ruleset):
        for chain in ("chain input", "chain forward", "chain docker_user", "chain output"):
            assert chain in ruleset

    def test_input_policy_is_drop(self, ruleset):
        assert "type filter hook input priority 0; policy drop;" in ruleset

    def test_forward_policy_is_drop(self, ruleset):
        assert "type filter hook forward priority 0; policy drop;" in ruleset

    def test_dynamic_sets_present(self, ruleset):
        for set_name in ("ssh_ratelimit", "syn_flood_guard", "portscan_blocklist"):
            assert f"set {set_name} {{" in ruleset
        assert ruleset.count("flags dynamic, timeout") >= 3

    def test_trusted_subnets_contain_admin_and_wireguard(self, ruleset, spec):
        assert spec.trusted_admin_cidr in ruleset
        assert spec.wireguard_subnet_cidr in ruleset
        assert spec.trusted_ipv6_cidr in ruleset

    def test_ssh_rate_limit_reflected(self, ruleset):
        assert "limit rate 15/minute burst 10 packets" in ruleset

    def test_custom_ssh_rate_reflected(self, prover):
        custom = NftablesPolicySpec(ssh_rate_per_minute=5, ssh_burst_packets=3)
        generated = prover.generate_ruleset(custom)
        assert "limit rate 5/minute burst 3 packets" in generated

    def test_public_ports_reflected(self, prover):
        custom = NftablesPolicySpec(public_tcp_ports=(8080, 8443))
        generated = prover.generate_ruleset(custom)
        assert "tcp dport { 8080, 8443 }" in generated

    def test_internal_ports_reflected(self, prover):
        custom = NftablesPolicySpec(internal_db_ports=(5432, 6379))
        generated = prover.generate_ruleset(custom)
        assert "ip saddr @trusted_subnets tcp dport { 5432, 6379 } accept" in generated

    def test_docker_user_chain_blocks_internal_ports(self, ruleset):
        assert "tcp dport { 5432, 9090, 9100 } drop" in ruleset

    def test_no_tabs_in_output(self, ruleset):
        assert "\t" not in ruleset

    def test_deterministic_output(self, prover, spec):
        assert prover.generate_ruleset(spec) == prover.generate_ruleset(spec)


class TestFeatureToggles:
    """Переключатели отдельных защитных механизмов."""

    def test_mss_clamping_enabled_by_default(self, ruleset):
        assert "maxseg size set rt mtu" in ruleset

    def test_mss_clamping_can_be_disabled(self, prover):
        generated = prover.generate_ruleset(NftablesPolicySpec(enable_mss_clamping=False))
        assert "maxseg size set rt mtu" not in generated

    def test_portscan_trap_can_be_disabled(self, prover):
        generated = prover.generate_ruleset(NftablesPolicySpec(enable_portscan_trap=False))
        assert "portscan_blocklist" not in generated
        assert "1433" not in generated

    def test_egress_filter_disabled_allows_output(self, prover):
        generated = prover.generate_ruleset(NftablesPolicySpec(enable_egress_filter=False))
        assert "type filter hook output priority 0; policy accept;" in generated

    def test_egress_filter_enabled_restricts_output(self, ruleset):
        assert "type filter hook output priority 0; policy drop;" in ruleset


# ---------------------------------------------------------------------------
# Структурная валидация
# ---------------------------------------------------------------------------
class TestStructuralValidation:
    """Проверка AST без прав CAP_NET_ADMIN."""

    def test_valid_ruleset_has_no_issues(self, prover, ruleset):
        assert prover.structural_validate(ruleset) == []

    def test_unbalanced_braces_detected(self, prover, ruleset):
        broken = ruleset.replace("    }\n", "", 1)
        issues = prover.structural_validate(broken)
        assert issues, "ожидалось обнаружение несбалансированных скобок"

    def test_missing_required_fragment_detected(self, prover, ruleset):
        broken = ruleset.replace("ct state established,related accept", "")
        issues = prover.structural_validate(broken)
        assert any("established,related" in i for i in issues)

    def test_missing_drop_policy_detected(self, prover):
        text = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy accept;\n }\n}\n"
        issues = prover.structural_validate(text)
        assert any("policy drop" in i for i in issues)


# ---------------------------------------------------------------------------
# Компиляторный прувер и round-trip TopoGuard
# ---------------------------------------------------------------------------
class TestProver:
    """Полный цикл доказательства корректности политики."""

    def test_prove_returns_proof_result(self, prover, spec):
        result = prover.prove_ruleset(spec)
        assert isinstance(result, NftablesProofResult)
        assert isinstance(result.generated_ruleset, str)

    def test_prove_syntax_valid(self, prover, spec):
        assert prover.prove_ruleset(spec).syntax_valid is True

    def test_prove_anti_lockout_safe(self, prover, spec):
        assert prover.prove_ruleset(spec).anti_lockout_safe is True

    def test_prove_k31_compliant(self, prover, spec):
        assert prover.prove_ruleset(spec).k31_compliant is True

    def test_prove_overall(self, prover, spec):
        assert prover.prove_ruleset(spec).is_proven is True

    def test_ast_summary_contains_k31(self, prover, spec):
        summary = json.loads(prover.prove_ruleset(spec).ast_summary_json)
        assert summary["k31_score"] == pytest.approx(1.0)
        assert summary["dangling_sets"] == []
        assert summary["docker_bypass_detected"] is False

    def test_roundtrip_generated_ruleset_passes_audit(self, prover, spec, ruleset):
        """Сгенерированный файрвол сам проходит независимый аудит TopoGuard."""
        exposed = {spec.ssh_port} | set(spec.public_tcp_ports) | set(spec.internal_db_ports)
        audit = IaCTopoGuardAnalyzer().analyze_topology(
            nft_text=ruleset,
            wireguard_conf="MTU = 1420",
            docker_enabled=True,
            exposed_ports=exposed,
        )
        assert audit.is_compliant is True
        assert audit.k31_score == pytest.approx(1.0)
        assert audit.unrestricted_mgmt_exposures == []

    def test_proof_report_is_readable(self, prover, spec):
        result = prover.prove_ruleset(spec)
        report = prover.proof_report(result)
        assert "PROVEN" in report
        assert "КТ-1" in report
        assert "k31" in report

    def test_to_dict_and_json(self, prover, spec):
        result = prover.prove_ruleset(spec)
        payload = result.to_dict()
        assert payload["syntax_valid"] is True
        parsed = json.loads(result.to_json())
        assert parsed["k31_compliant"] is True


# ---------------------------------------------------------------------------
# Валидация спецификации и запись файла
# ---------------------------------------------------------------------------
class TestSpecValidation:
    """Защита от некорректных входных параметров."""

    def test_port_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="порт вне диапазона"):
            NftablesPolicySpec(ssh_port=70000).validate()

    def test_zero_rate_rejected(self):
        with pytest.raises(ValueError, match="ssh_rate_per_minute"):
            NftablesPolicySpec(ssh_rate_per_minute=0).validate()

    def test_bad_cidr_rejected(self):
        with pytest.raises(ValueError, match="CIDR"):
            NftablesPolicySpec(trusted_admin_cidr="10.30.1.0").validate()

    def test_write_ruleset_creates_file(self, prover, spec, workdir):
        target = workdir / "etc" / "nftables.conf"
        written = prover.write_ruleset(target, spec)
        assert written == target
        assert target.exists()
        assert target.read_text(encoding="utf-8") == prover.generate_ruleset(spec)


def test_default_spec_matches_team_b3_baseline():
    """Значения по умолчанию соответствуют ТЗ команды Б3."""
    spec = NftablesPolicySpec()
    assert spec.trusted_admin_cidr == "10.30.1.0/24"
    assert spec.wireguard_subnet_cidr == "10.99.0.0/24"
    assert spec.ssh_port == 22
    assert spec.public_tcp_ports == (80, 443)
    assert spec.internal_db_ports == (5432, 9090, 9100)
    Path  # noqa: B018 - явная ссылка на импорт для читаемости
