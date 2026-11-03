# Autonomous Linux & NixOS Hardening Copilot

**Команда Б3** · ФГАОУ ВО «ОмГУ им. Ф. М. Достоевского» · Кафедра кибербезопасности (КИБ)
Специальность 10.05.01 «Компьютерная безопасность» · гр. МБС-301-О-01

Кожемякин Дмитрий Николаевич ([@kwerel](https://github.com/kwerel)) —
Вебер Александр Александрович ([@mbr_DIGMA_PRO_Sprint](https://github.com/mbr_DIGMA_PRO_Sprint))

Руководитель практики: старший преподаватель Вильховский Данил Эдуардович

---

## Что это

Автономный ИИ-агент аудита, верификации и харденинга Linux и NixOS. Комплекс
замыкает контур управления конфигурацией в четырёх фазах:

```
Sense  ->  Triage & Synthesize  ->  Canary Dry-Run  ->  Transactional Apply
(Меркл)     (TopoGuard + LLM)       (компиляторы)       (Dead-Man's Switch)
```

| Слой | Назначение | Модули |
|------|------------|--------|
| 1. Sense | Детерминированный съём телеметрии, дерево Меркла SHA-256, дрейф за O(log K) | `src/scanner/linux_state_collector.py` |
| 2. Triage | Граф сетевой достижимости, сжатие предупреждений, показатель k31 | `src/topoguard/iac_topoguard_ast.py` |
| 3. Verify | Компиляторная проверка патчей в Canary-песочнице, Anti-Lockout Guard | `src/remediation/canary_verifier.py`, `src/remediation/langgraph_hardening_agent.py` |
| 4. Commit | Криптографический журнал ревизий по ГОСТ Р 34.11-2012 и атомарный откат | `src/crypto/streebog_rollback_ledger.py`, `migrations/001_hardening_ledger.sql` |

## Ключевая идея TopoGuard

Классические сканеры (OpenSCAP, Lynis, Checkov, Trivy) дают сотни строчных
предупреждений и не видят сквозной граф путей атаки. TopoGuard строит
ориентированный граф `G = (V, E)`, где вершины — зоны, интерфейсы, цепочки
фильтрации и сокеты служб, а рёбра размечены предикатом фильтрации
`(proto, src_cidr, dst_port, ct_state, rate_limit, verdict)`, и проверяет пять
инвариантов Zero-Trust:

| Инвариант | Что проверяется |
|-----------|-----------------|
| **INV-1** | Из `0.0.0.0/0` нет маршрута к `22/tcp` без rate-limit/бастиона и к `5432`, `6379`, `9090`, `9100` |
| **INV-2** | Проброс портов Docker/Podman не обходит хостовый `input` (нужна `DOCKER-USER` либо `policy drop` в `forward`) |
| **INV-3** | Нет висячих ссылок `dangling_set` — правил на необъявленные или пустые наборы адресов |
| **INV-4** | MTU туннеля WireGuard в диапазоне `1280..1420` и присутствует `tcp option maxseg size set rt mtu` |
| **INV-5** | Показатель защищённости периметра `k31` рассчитан и сжат в уникальные маршруты атаки |

## Быстрый старт

Требуется Python 3.12+.

```bash
# 1. Зависимости для разработки
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e ".[dev]"

# 2. Тесты
pytest

# 3. Аудит уязвимого узла
python -m topoguard audit tests/fixtures/insecure

# 4. Аудит эталонного узла (используется в CI как smoke-тест)
python -m topoguard audit tests/fixtures/hardened --fail-on-violation

# 5. Синтез и доказательство эталонной политики nftables
python -m topoguard prove --out build/nftables.conf

# 6. Сквозное демо всех четырёх подсистем Роли 2
python scripts/demo_b3.py --json build/demo.json
```

Пример вывода на уязвимой конфигурации:

```
TopoGuard audit :: tests\fixtures\insecure
  rules parsed .......... 5
  dangling sets ......... allowed_admin
  docker bypass ......... YES
  wireguard mtu ok ...... NO
  mss clamping ok ....... NO
  k31 (perimeter) ....... 0.0000
  noise reduction ....... 85.00%

  Attack paths:
    0.0.0.0/0 (Internet) -> [input] -> tcp/22 (HIGH)
    0.0.0.0/0 (Internet) -> [input] -> tcp/5432 (CRITICAL)
    0.0.0.0/0 (Internet) -> [input] -> tcp/9090 (CRITICAL)

  VERDICT: FAILED
```

## Структура репозитория

```
.
├── flake.nix                             # NixOS 25.11: VM 301..304 + devShell
├── nixos/
│   ├── common.nix                        # база стенда, статическая адресация
│   ├── hardening-baseline.nix            # sysctl, auditd, sshd, изоляция служб
│   ├── vm-301-copilot-gpu.nix            # RTX 5080 passthrough, vLLM, Qdrant
│   ├── vm-302-vulnerable-target.nix      # намеренно уязвимый LAPP-стенд
│   ├── vm-303-hardened-canary.nix        # компиляторная Canary-песочница
│   └── vm-304-audit-server.nix           # PostgreSQL 16, Prometheus, Grafana
├── src/
│   ├── topoguard/
│   │   ├── iac_topoguard_ast.py          # граф достижимости, 5 инвариантов, k31
│   │   ├── nftables_generator_and_prover.py
│   │   └── cli.py                        # python -m topoguard audit|prove
│   ├── runtime/
│   │   └── ebpf_systemd_sandbox_enforcer.py
│   └── crypto/
│       └── streebog_rollback_ledger.py
├── migrations/
│   └── 001_hardening_ledger.sql
├── scripts/
│   └── demo_b3.py                        # сквозной прогон всех подсистем
├── tests/
│   ├── fixtures/
│   │   ├── insecure/                     # уязвимый узел
│   │   ├── hardened/                     # эталонный узел
│   │   └── systemd-analyze-security.txt
│   ├── test_topoguard.py
│   ├── test_nftables_prover.py
│   ├── test_sandbox_enforcer.py
│   └── test_streebog_ledger.py
└── pyproject.toml
```

## Нормативная база

- Приказ ФСТЭК России № 17 от 17.02.2015 (ГИС)
- Приказ ФСТЭК России № 21 от 18.02.2013 (ИСПДн)
- Приказ ФСТЭК России № 117 от 25.12.2017 (АСУ ТП)
- Профиль защиты операционных систем типа «А» четвёртого класса защищённости
- CIS Linux Benchmark v3.0
- ГОСТ Р 34.11-2012 «Стрибог-256»
- ГОСТ Р 59548-2022

## Статус разработки

| Модуль | Задача WBS | Статус |
|--------|-----------|--------|
| `iac_topoguard_ast.py` | B3-06, B3-08, B3-10 | ✅ реализован, 44 теста |
| `nftables_generator_and_prover.py` | B3-12, B3-14 | ✅ реализован, round-trip `k31 = 1.0` |
| `ebpf_systemd_sandbox_enforcer.py` | B3-16 | ✅ реализован, 51 тест |
| `streebog_rollback_ledger.py` + SQL | B3-18 | ✅ реализован, векторы ГОСТ сошлись |
| NixOS flake + VM 301..304 | B3-02, B3-04 | ✅ реализован, `nix flake check` в CI |
| Сквозное демо `scripts/demo_b3.py` | B3-34, B3-36 | ✅ прогон зелёный |

## Лицензия

MIT — см. [LICENSE](LICENSE).
