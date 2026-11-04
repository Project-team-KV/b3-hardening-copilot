"""Тесты интерфейса командной строки TopoGuard.

Проверяют коды возврата, вывод и отсутствие регрессий при использовании
флага ``--docker`` на каталоге с конфигурациями.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from topoguard.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestAuditCommand:
    """Подкоманда `audit`."""

    def test_clean_node_returns_zero(self, capsys):
        """Эталонный узел проходит проверку с кодом 0."""
        code = main(["audit", str(FIXTURES / "hardened")])
        assert code == 0
        assert "PASSED" in capsys.readouterr().out

    def test_vulnerable_node_with_fail_flag_returns_two(self, capsys):
        """Флаг --fail-on-violation возвращает код 2 при нарушениях."""
        code = main(["audit", str(FIXTURES / "insecure"), "--fail-on-violation"])
        assert code == 2
        assert "FAILED" in capsys.readouterr().out

    def test_missing_path_returns_two(self, capsys):
        """Несуществующий путь даёт понятную ошибку, а не трейсбек."""
        code = main(["audit", str(FIXTURES / "no-such-path")])
        assert code == 2
        assert "не найден" in capsys.readouterr().err

    def test_json_output_is_parseable(self, capsys):
        """Флаг --json печатает валидный JSON."""
        main(["audit", str(FIXTURES / "insecure"), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["k31_score"] == pytest.approx(0.0)

    def test_docker_flag_does_not_hide_wireguard_findings(self, capsys):
        """Регрессия: --docker не должен терять данные WireGuard и iptables."""
        main(["audit", str(FIXTURES / "insecure"), "--json"])
        without_flag = json.loads(capsys.readouterr().out)

        main(["audit", str(FIXTURES / "insecure"), "--docker", "--json"])
        with_flag = json.loads(capsys.readouterr().out)

        assert with_flag["wireguard_mtu_ok"] == without_flag["wireguard_mtu_ok"]
        assert with_flag["mss_clamping_ok"] == without_flag["mss_clamping_ok"]
        assert len(with_flag["unrestricted_mgmt_exposures"]) == len(
            without_flag["unrestricted_mgmt_exposures"]
        )

    def test_single_file_audit(self, capsys):
        """Аудит отдельного файла конфигурации."""
        target = FIXTURES / "insecure" / "nftables.conf"
        code = main(["audit", str(target)])
        assert code == 0
        assert "TopoGuard audit" in capsys.readouterr().out


class TestProveCommand:
    """Подкоманда `prove`."""

    def test_prove_returns_zero(self, capsys):
        """Штатная спецификация доказывается с кодом 0."""
        code = main(["prove"])
        assert code == 0
        assert "PROVEN" in capsys.readouterr().out

    def test_prove_writes_ruleset(self, capsys, workdir):
        """Флаг --out записывает сгенерированный файл."""
        target = workdir / "nftables.conf"
        code = main(["prove", "--out", str(target)])
        assert code == 0
        assert target.exists()
        assert "table inet filter {" in target.read_text(encoding="utf-8")

    def test_prove_json_is_parseable(self, capsys):
        """Флаг --json печатает результат в машиночитаемом виде."""
        main(["prove", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["syntax_valid"] is True
        assert payload["k31_compliant"] is True

    def test_prove_print_ruleset(self, capsys):
        """Флаг --print-ruleset печатает сам файл политики."""
        main(["prove", "--print-ruleset"])
        out = capsys.readouterr().out
        assert "flush ruleset" in out
        assert "policy drop;" in out
