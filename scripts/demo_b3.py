"""Сквозной демонстрационный сценарий команды Б3 (Роль 2).

Прогоняет полный контур на локальных данных — без стенда и без GPU:

    1. Аудит уязвимого узла      -> маршруты атаки, нарушенные инварианты;
    2. Синтез эталонной политики -> nftables.conf + доказательство k31 = 1.0;
    3. Повторный аудит синтеза   -> подтверждение, что патч закрывает дыры;
    4. Изоляция служб            -> drop-in профили systemd + eBPF LSM;
    5. Журнал ревизий            -> «Стрибог-256», целостность, откат.

Запуск::

    python scripts/demo_b3.py
    python scripts/demo_b3.py --json build/demo.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from crypto.streebog_rollback_ledger import (  # noqa: E402
    StreebogRollbackLedger,
    streebog256_hex,
)
from runtime.ebpf_systemd_sandbox_enforcer import SystemdEbpfSandboxEnforcer  # noqa: E402
from topoguard.iac_topoguard_ast import IaCTopoGuardAnalyzer  # noqa: E402
from topoguard.nftables_generator_and_prover import (  # noqa: E402
    NftablesGeneratorAndProver,
    NftablesPolicySpec,
)

FIXTURES = ROOT / "tests" / "fixtures"
BUILD = ROOT / "build"

LINE = "=" * 72


def section(title: str) -> None:
    """Печатает заголовок раздела демонстрации."""
    print()
    print(LINE)
    print(title)
    print(LINE)


def step_audit() -> dict:
    """Шаг 1: аудит уязвимого узла VM 302."""
    section("ШАГ 1. Аудит уязвимого узла (VM 302) — TopoGuard")
    analyzer = IaCTopoGuardAnalyzer()
    report = analyzer.analyze_directory(FIXTURES / "insecure")

    print(f"  разобрано правил ......... {report.total_raw_rules}")
    print(f"  пустые наборы (dangling) . {report.dangling_sets or '-'}")
    print(f"  обход через Docker ....... {'ДА' if report.docker_bypass_detected else 'нет'}")
    print(f"  MTU WireGuard корректен .. {'да' if report.wireguard_mtu_ok else 'НЕТ'}")
    print(f"  MSS Clamping ............. {'есть' if report.mss_clamping_ok else 'НЕТ'}")
    print(f"  показатель k31 ........... {report.k31_score:.2f}")
    print()
    print("  Маршруты атаки из 0.0.0.0/0:")
    for edge in report.unrestricted_mgmt_exposures:
        print(f"    - {edge.as_route()}")
    print()
    print(f"  Итог: {'PASSED' if report.is_compliant else 'FAILED'}")
    print(f"  Нарушено инвариантов: {len(report.failed_invariants)}")
    for item in report.failed_invariants:
        print(f"    - {item}")
    return report.to_dict()


def step_prove() -> dict:
    """Шаг 2-3: синтез эталонной политики и её round-trip проверка."""
    section("ШАГ 2. Синтез эталонного nftables.conf — NftablesGeneratorAndProver")
    spec = NftablesPolicySpec()
    prover = NftablesGeneratorAndProver()
    result = prover.prove_ruleset(spec)

    BUILD.mkdir(exist_ok=True)
    prover.write_ruleset(BUILD / "nftables.conf", spec)

    print(prover.proof_report(result))
    print(f"  ruleset записан .......... {BUILD / 'nftables.conf'}")

    section("ШАГ 3. Повторный аудит уже защищённого узла")
    analyzer = IaCTopoGuardAnalyzer()
    audit = analyzer.analyze_topology(
        nft_text=result.generated_ruleset,
        wireguard_conf="MTU = 1420",
        docker_enabled=True,
        exposed_ports={22, 80, 443, 5432, 9090, 9100},
    )
    print(f"  показатель k31 ........... {audit.k31_score:.2f}")
    print(f"  маршрутов атаки .......... {len(audit.unrestricted_mgmt_exposures)}")
    print(f"  нарушенных инвариантов ... {len(audit.failed_invariants)}")
    print(f"  Итог: {'PASSED' if audit.is_compliant else 'FAILED'}")
    return {
        "proof": {
            "syntax_valid": result.syntax_valid,
            "anti_lockout_safe": result.anti_lockout_safe,
            "k31_compliant": result.k31_compliant,
            "compiler_output": result.compiler_output,
        },
        "audit_after_patch": audit.to_dict(),
    }


def step_sandbox() -> dict:
    """Шаг 4: генерация профилей изоляции служб."""
    section("ШАГ 4. Изоляция служб — systemd / seccomp / eBPF LSM")
    enforcer = SystemdEbpfSandboxEnforcer()
    raw = (FIXTURES / "systemd-analyze-security.txt").read_text(encoding="utf-8")
    profiles = enforcer.enforce_all_vulnerable_units(raw)

    print(enforcer.render_summary(profiles))
    print()

    written = enforcer.write_profiles(profiles, BUILD / "root")
    print(f"  drop-in профилей записано  {len(written)}")
    for path in written:
        print(f"    - {path.relative_to(ROOT)}")

    worst = max(profiles, key=lambda p: p.estimated_score_before)
    print()
    print(f"  Пример eBPF LSM программы для {worst.unit_name}:")
    for line in worst.ebpf_lsm_policy_program.splitlines()[:14]:
        print(f"    {line}")

    return {
        "profiles": [
            {
                "unit": p.unit_name,
                "dropin": p.dropin_path,
                "before": p.estimated_score_before,
                "after": p.estimated_score_after,
                "verdict": p.verdict_after,
            }
            for p in profiles
        ]
    }


def step_ledger() -> dict:
    """Шаг 5: журнал ревизий «Стрибог-256» и транзакционный откат."""
    section("ШАГ 5. Журнал ревизий ГОСТ Р 34.11-2012 и Dead-Man's Switch")

    print(f"  H256(M1) = {streebog256_hex(b'012345678901234567890123456789012345678901234567890123456789012')}")
    print("  (эталон ГОСТ Р 34.11-2012 / RFC 6986)")

    ledger = StreebogRollbackLedger()
    ledger.record_revision(
        tx_id="tx_demo_01",
        target_host="vm-302",
        merkle_root_before="a" * 64,
        merkle_root_after="b" * 64,
        patch_bundle={"nftables": "policy drop", "ssh": "rate-limit 3/minute"},
    )

    committed = ledger.execute_transactional_hardening(
        tx_id="tx_demo_02",
        target_host="vm-302",
        merkle_before="b" * 64,
        merkle_after="c" * 64,
        patch_bundle={"sshd": "PermitRootLogin no"},
        apply_fn=lambda: None,
        healthcheck_fn=lambda: True,
        rollback_fn=lambda: None,
        watchdog_timeout_sec=8.0,
    )

    rolled_back = ledger.execute_transactional_hardening(
        tx_id="tx_demo_03",
        target_host="vm-302",
        merkle_before="c" * 64,
        merkle_after="d" * 64,
        patch_bundle={"nginx": "TLS 1.3 only"},
        apply_fn=lambda: None,
        healthcheck_fn=lambda: False,   # HTTP 200 OK не получен
        rollback_fn=lambda: None,
    )

    ok, message = ledger.verify_ledger_integrity()
    print()
    print(f"  ревизий в журнале ........ {len(ledger)}")
    print(f"  tx_demo_02 ............... {committed.status}")
    print(f"  tx_demo_03 ............... {rolled_back.status} "
          f"(откат {rolled_back.rollback_duration_ms} мс)")
    print(f"  целостность цепочки ...... {message}")

    # Демонстрация обнаружения подмены.
    ledger.entries[0].patch_bundle["nftables"] = "policy accept"
    tampered_ok, tampered_msg = ledger.verify_ledger_integrity()
    print(f"  после подмены записи ..... {tampered_msg}")

    out = ledger.export_jsonl(BUILD / "ledger.jsonl")
    print(f"  выгрузка JSONL ........... {out.relative_to(ROOT)}")

    return {
        "revisions": len(ledger),
        "integrity_before_tamper": {"ok": ok, "message": message},
        "integrity_after_tamper": {"ok": tampered_ok, "message": tampered_msg},
        "committed_tx": committed.to_dict(),
        "rolled_back_tx": rolled_back.to_dict(),
    }


def main(argv: list[str] | None = None) -> int:
    """Запускает все шаги демонстрации и сохраняет JSON-протокол."""
    parser = argparse.ArgumentParser(description="Сквозное демо команды Б3 (Роль 2)")
    parser.add_argument("--json", type=Path, default=None, help="куда сохранить протокол")
    args = parser.parse_args(argv)

    print(LINE)
    print("Команда Б3 — Autonomous Linux & NixOS Hardening Copilot")
    print("Вебер А. А. (@mbr_DIGMA_PRO_Sprint), Роль 2 — сквозной прогон")
    print(LINE)

    protocol = {
        "audit_before": step_audit(),
        **step_prove(),
        "sandbox": step_sandbox(),
        "ledger": step_ledger(),
    }

    section("ИТОГ")
    print("  Все четыре подсистемы Роли 2 отработали в одном контуре.")
    print(f"  k31 до патча: {protocol['audit_before']['k31_score']:.2f}")
    print(f"  k31 после патча: {protocol['audit_after_patch']['k31_score']:.2f}")

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(protocol, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"  протокол сохранён ....... {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
