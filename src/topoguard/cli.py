# src/topoguard/cli.py
# Владелец модуля: Вебер Александр Александрович (@mbr_DIGMA_PRO_Sprint), Команда Б3
"""CLI-интерфейс графового анализатора TopoGuard.

Примеры запуска::

    python -m topoguard audit tests/fixtures/insecure
    python -m topoguard audit /etc --json --fail-on-violation
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .iac_topoguard_ast import IaCTopoGuardAnalyzer, TopoGuardAuditReport

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[96m",
    "LOW": "\033[92m",
}
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"


def _supports_color() -> bool:
    """Есть ли у потока вывода поддержка ANSI-цветов."""
    return sys.stdout.isatty()


def _paint(text: str, color: str) -> str:
    """Окрашивает текст, если терминал поддерживает цвета."""
    if not _supports_color():
        return text
    return f"{color}{text}{RESET}"


def render_report(report: TopoGuardAuditReport, target: str) -> str:
    """Формирует человекочитаемый отчёт для терминала и протокола испытаний."""
    verdict = (
        _paint("PASSED", GREEN) if report.is_compliant else _paint("FAILED", RED)
    )
    lines = [
        f"{_paint('TopoGuard audit', BOLD)} :: {target}",
        f"  rules parsed .......... {report.total_raw_rules}",
        f"  declared sets ......... {', '.join(report.declared_sets) or '-'}",
        f"  dangling sets ......... {', '.join(report.dangling_sets) or '-'}",
        f"  docker bypass ......... {'YES' if report.docker_bypass_detected else 'no'}",
        f"  wireguard mtu ok ...... {'yes' if report.wireguard_mtu_ok else 'NO'}",
        f"  mss clamping ok ....... {'yes' if report.mss_clamping_ok else 'NO'}",
        f"  k31 (perimeter) ....... {report.k31_score:.4f}",
        f"  noise reduction ....... {report.noise_reduction_ratio:.2%}",
        "",
    ]

    if report.unrestricted_mgmt_exposures:
        lines.append(_paint("  Attack paths:", BOLD))
        for edge in report.unrestricted_mgmt_exposures:
            color = SEVERITY_COLOR.get(edge.severity, "")
            lines.append(f"    {_paint(edge.as_route(), color)}")
            lines.append(f"      reason: {edge.reason}")
    else:
        lines.append(_paint("  No attack paths from 0.0.0.0/0", GREEN))

    if report.failed_invariants:
        lines.append("")
        lines.append(_paint("  Failed invariants:", BOLD))
        for item in report.failed_invariants:
            lines.append(f"    - {item}")

    lines.append("")
    lines.append(f"  VERDICT: {verdict}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Собирает парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(
        prog="topoguard",
        description="IaC TopoGuard — статический анализ сетевой достижимости Linux-узла",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit", help="проверить каталог или файл с конфигурацией узла"
    )
    audit.add_argument(
        "path",
        type=Path,
        help="каталог с nftables.conf / *.rules / wg*.conf либо отдельный файл",
    )
    audit.add_argument("--json", action="store_true", help="вывести отчёт в JSON")
    audit.add_argument(
        "--docker",
        action="store_true",
        help="учитывать проброс портов Docker/Podman",
    )
    audit.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="вернуть код 2, если инварианты нарушены (для CI)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI. Возвращает код завершения процесса."""
    args = build_parser().parse_args(argv)
    analyzer = IaCTopoGuardAnalyzer()
    target: Path = args.path

    if target.is_dir():
        report = analyzer.analyze_directory(target)
        if args.docker:
            nft = "\n".join(
                p.read_text(encoding="utf-8", errors="replace")
                for p in sorted(target.rglob("nftables.conf"))
            )
            report = analyzer.analyze_topology(
                nft_text=nft, docker_enabled=True, base_dir=target
            )
    else:
        text = target.read_text(encoding="utf-8", errors="replace")
        report = analyzer.analyze_topology(
            nft_text=text, docker_enabled=args.docker, base_dir=target.parent
        )

    if args.json:
        print(report.to_json())
    else:
        print(render_report(report, str(target)))

    if args.fail_on_violation and not report.is_compliant:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
