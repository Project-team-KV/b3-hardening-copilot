"""Тесты генератора профилей изоляции systemd / seccomp / eBPF LSM.

Проверяют:
    * разбор реального вывода `systemd-analyze security --no-pager`;
    * состав drop-in профиля и корректность пути установки;
    * эквивалентность NixOS-фрагмента;
    * синтаксическую целостность eBPF LSM программы;
    * снижение Exposure Score с 9.2 UNSAFE до < 1.8 OK.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runtime.ebpf_systemd_sandbox_enforcer import (
    TARGET_SCORE,
    GeneratedSandboxProfile,
    ServiceSandboxRequirements,
    SystemdEbpfSandboxEnforcer,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def enforcer() -> SystemdEbpfSandboxEnforcer:
    """Новый генератор профилей для каждого теста."""
    return SystemdEbpfSandboxEnforcer()


@pytest.fixture()
def analyze_output() -> str:
    """Реалистичный вывод `systemd-analyze security`."""
    return (FIXTURES / "systemd-analyze-security.txt").read_text(encoding="utf-8")


@pytest.fixture()
def profile(enforcer) -> GeneratedSandboxProfile:
    """Профиль для самой уязвимой службы стенда."""
    return enforcer.generate_sandbox_profile(
        enforcer.SERVICE_PRESETS["legacy-telemetry-agent.service"]
    )


# ---------------------------------------------------------------------------
# Разбор вывода systemd-analyze security
# ---------------------------------------------------------------------------
class TestAnalyzeParsing:
    """Парсер табличного вывода systemd."""

    def test_parses_all_rows(self, enforcer, analyze_output):
        rows = enforcer.parse_systemd_analyze_table(analyze_output)
        assert len(rows) == 6

    def test_sorted_by_score_desc(self, enforcer, analyze_output):
        rows = enforcer.parse_systemd_analyze_table(analyze_output)
        scores = [row[1] for row in rows]
        assert scores == sorted(scores, reverse=True)

    def test_extracts_unit_and_verdict(self, enforcer, analyze_output):
        rows = dict(
            (row[0], (row[1], row[2]))
            for row in enforcer.parse_systemd_analyze_table(analyze_output)
        )
        assert rows["nginx.service"] == (9.6, "UNSAFE")
        assert rows["cups.service"] == (6.2, "MEDIUM")
        assert rows["sshd.service"] == (2.1, "OK")

    def test_ignores_header_and_junk(self, enforcer):
        rows = enforcer.parse_systemd_analyze_table(
            "  NAME   DESCRIPTION   EXPOSURE\nnot a row\n"
        )
        assert rows == []

    def test_handles_check_and_cross_markers(self, enforcer):
        text = (
            "✓ good.service  Fine service  1.0 OK\n"
            "✗ bad.service   Bad service   8.5 UNSAFE\n"
        )
        rows = enforcer.parse_systemd_analyze_table(text)
        assert [row[0] for row in rows] == ["bad.service", "good.service"]


# ---------------------------------------------------------------------------
# Состав drop-in профиля
# ---------------------------------------------------------------------------
class TestDropinContent:
    """Содержимое drop-in файла systemd."""

    def test_dropin_path_is_correct(self, profile):
        assert (
            profile.dropin_path
            == "/etc/systemd/system/legacy-telemetry-agent.service.d/99-b3-hardening.conf"
        )

    def test_dropin_path_has_single_service_suffix(self, profile):
        assert profile.dropin_path.count(".service") == 1

    def test_contains_section_header(self, profile):
        assert "[Service]" in profile.systemd_dropin_content

    @pytest.mark.parametrize(
        "directive",
        [
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "NoNewPrivileges=yes",
            "ProtectKernelModules=yes",
            "MemoryDenyWriteExecute=yes",
            "UMask=0077",
            "SystemCallFilter=@system-service",
        ],
    )
    def test_contains_hardening_directive(self, profile, directive):
        assert directive in profile.systemd_dropin_content

    def test_restricts_privileged_syscalls(self, profile):
        assert "~@privileged" in profile.systemd_dropin_content
        assert "@resources" in profile.systemd_dropin_content

    def test_read_write_paths_present(self, profile):
        assert "ReadWritePaths=/var/log/telemetry" in profile.systemd_dropin_content

    def test_network_service_keeps_network(self, profile):
        assert "PrivateNetwork=no" in profile.systemd_dropin_content

    def test_socket_activated_service_is_network_isolated(self, enforcer):
        req = ServiceSandboxRequirements(
            unit_name="worker.service", needs_network=False, writable_paths=()
        )
        generated = enforcer.generate_sandbox_profile(req)
        assert "PrivateNetwork=yes" in generated.systemd_dropin_content
        assert "RestrictAddressFamilies=AF_UNIX" in generated.systemd_dropin_content

    def test_privileged_port_adds_capability(self, enforcer):
        generated = enforcer.generate_sandbox_profile(
            enforcer.SERVICE_PRESETS["nginx.service"]
        )
        assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in generated.systemd_dropin_content

    def test_service_without_privileged_port_has_empty_caps(self, enforcer):
        generated = enforcer.generate_sandbox_profile(
            enforcer.SERVICE_PRESETS["postgresql.service"]
        )
        assert "CapabilityBoundingSet=\n" in generated.systemd_dropin_content


# ---------------------------------------------------------------------------
# NixOS-фрагмент
# ---------------------------------------------------------------------------
class TestNixosSnippet:
    """Эквивалентная конфигурация NixOS."""

    def test_declares_service_config(self, profile):
        assert 'systemd.services."legacy-telemetry-agent".serviceConfig = {' in (
            profile.nixos_service_config_snippet
        )

    def test_uses_nix_booleans(self, profile):
        assert "ProtectSystem = \"strict\";" in profile.nixos_service_config_snippet
        assert "ProtectHome = true;" in profile.nixos_service_config_snippet

    def test_lists_are_quoted(self, profile):
        assert '"@system-service"' in profile.nixos_service_config_snippet

    def test_read_write_paths_rendered(self, profile):
        assert 'ReadWritePaths = [ "/var/log/telemetry" ];' in (
            profile.nixos_service_config_snippet
        )


# ---------------------------------------------------------------------------
# eBPF LSM программа
# ---------------------------------------------------------------------------
class TestEbpfProgram:
    """Синтезируемая программа ядерного контроля."""

    def test_has_lsm_attach_point(self, profile):
        assert 'SEC("lsm/bprm_check_security")' in profile.ebpf_lsm_policy_program

    def test_has_license(self, profile):
        assert 'SEC("license") = "GPL"' in profile.ebpf_lsm_policy_program

    def test_targets_unit_comm(self, profile):
        assert '#define B3_UNIT_COMM "legacy-telemetry-agent"' in (
            profile.ebpf_lsm_policy_program
        )

    def test_denies_shell_and_escalation(self, profile):
        program = profile.ebpf_lsm_policy_program
        for binary in ("/bin/sh", "/bin/bash", "/usr/bin/sudo", "/usr/bin/su"):
            assert f'"{binary}"' in program

    def test_returns_eperm_on_denied(self, profile):
        assert "return -EPERM;" in profile.ebpf_lsm_policy_program

    def test_allowed_prefixes_from_writable_paths(self, profile):
        assert '"/var/log/telemetry",' in profile.ebpf_lsm_policy_program

    def test_braces_balanced(self, profile):
        program = profile.ebpf_lsm_policy_program
        assert program.count("{") == program.count("}")

    def test_program_does_not_contain_placeholders(self, profile):
        for placeholder in ("__UNIT__", "__PATHS__", "__ALLOWED_LIST__"):
            assert placeholder not in profile.ebpf_lsm_policy_program


# ---------------------------------------------------------------------------
# Оценка экспозиции
# ---------------------------------------------------------------------------
class TestExposureScore:
    """Снижение Exposure Score и вердикт."""

    def test_legacy_agent_drops_below_target(self, profile):
        assert profile.estimated_score_before == pytest.approx(9.2)
        assert profile.estimated_score_after < TARGET_SCORE
        assert profile.verdict_after == "OK"

    def test_never_below_floor(self, enforcer):
        """Оценка не опускается ниже разумного минимума."""
        req = ServiceSandboxRequirements(unit_name="tiny.service", initial_exposure_score=1.0)
        generated = enforcer.generate_sandbox_profile(req)
        assert generated.estimated_score_after >= 1.0

    @pytest.mark.parametrize("initial", [0.0, 0.3, 0.5, 0.9])
    def test_already_hardened_service_not_worsened(self, enforcer, initial):
        """Служба с низкой оценкой после «укрепления» не становится хуже."""
        req = ServiceSandboxRequirements(
            unit_name="safe.service", initial_exposure_score=initial
        )
        generated = enforcer.generate_sandbox_profile(req)
        assert generated.estimated_score_after <= initial

    def test_is_hardened_property(self, profile):
        assert profile.is_hardened is True

    def test_verdict_mapping(self, enforcer):
        assert enforcer._verdict_for(1.5) == "OK"
        assert enforcer._verdict_for(3.0) == "MEDIUM"
        assert enforcer._verdict_for(6.5) == "EXPOSED"
        assert enforcer._verdict_for(9.0) == "UNSAFE"


# ---------------------------------------------------------------------------
# Пакетная обработка и запись файлов
# ---------------------------------------------------------------------------
class TestBatchEnforcement:
    """Обработка всего отчёта systemd-analyze security."""

    def test_only_vulnerable_units_get_profiles(self, enforcer, analyze_output):
        profiles = enforcer.enforce_all_vulnerable_units(analyze_output)
        units = {p.unit_name for p in profiles}
        assert units == {
            "nginx.service",
            "postgresql.service",
            "legacy-telemetry-agent.service",
            "cups.service",
        }
        assert "sshd.service" not in units

    def test_custom_threshold(self, enforcer, analyze_output):
        profiles = enforcer.enforce_all_vulnerable_units(analyze_output, threshold=7.0)
        units = {p.unit_name for p in profiles}
        assert units == {"nginx.service", "postgresql.service", "legacy-telemetry-agent.service"}

    def test_presets_applied(self, enforcer, analyze_output):
        profiles = {p.unit_name: p for p in enforcer.enforce_all_vulnerable_units(analyze_output)}
        nginx = profiles["nginx.service"].systemd_dropin_content
        assert "/var/cache/nginx" in nginx
        assert "ReadWritePaths=" in nginx

    def test_unknown_unit_gets_generic_profile(self, enforcer, analyze_output):
        profiles = {p.unit_name: p for p in enforcer.enforce_all_vulnerable_units(analyze_output)}
        assert "cups.service" in profiles
        assert profiles["cups.service"].estimated_score_before == pytest.approx(6.2)

    def test_write_profiles_creates_dropins(self, enforcer, analyze_output, workdir):
        profiles = enforcer.enforce_all_vulnerable_units(analyze_output)
        written = enforcer.write_profiles(profiles, workdir)
        assert len(written) == 4
        for path in written:
            assert path.exists()
            assert "99-b3-hardening.conf" in path.name
            assert "[Service]" in path.read_text(encoding="utf-8")

    def test_write_profiles_preserves_directory_layout(self, enforcer, analyze_output, workdir):
        profiles = enforcer.enforce_all_vulnerable_units(analyze_output)
        enforcer.write_profiles(profiles, workdir)
        expected = workdir / "etc/systemd/system/nginx.service.d/99-b3-hardening.conf"
        assert expected.exists()

    def test_render_summary_table(self, enforcer, analyze_output):
        profiles = enforcer.enforce_all_vulnerable_units(analyze_output)
        table = enforcer.render_summary(profiles)
        assert "unit" in table and "before" in table and "after" in table
        assert "nginx.service" in table
        assert table.count("\n") >= len(profiles)

    def test_to_dict_roundtrip(self, profile):
        payload = profile.to_dict()
        assert payload["unit_name"] == profile.unit_name
        assert payload["estimated_score_after"] == profile.estimated_score_after


# ---------------------------------------------------------------------------
# Валидация требований
# ---------------------------------------------------------------------------
class TestRequirementsValidation:
    """Защита от некорректных входных требований."""

    def test_invalid_unit_name_rejected(self):
        with pytest.raises(ValueError, match="systemd-юнита"):
            ServiceSandboxRequirements(unit_name="bad unit").validate()

    def test_relative_path_rejected(self):
        with pytest.raises(ValueError, match="абсолютным"):
            ServiceSandboxRequirements(
                unit_name="ok.service", writable_paths=("var/lib",)
            ).validate()

    def test_score_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="0..10"):
            ServiceSandboxRequirements(
                unit_name="ok.service", initial_exposure_score=11.0
            ).validate()

    def test_service_stem(self):
        req = ServiceSandboxRequirements(unit_name="nginx.service")
        assert req.service_stem == "nginx"
