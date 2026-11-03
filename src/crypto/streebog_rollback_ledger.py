# src/crypto/streebog_rollback_ledger.py
# Владелец модуля: Вебер Александр Александрович (@mbr_DIGMA_PRO_Sprint), Команда Б3
"""Криптографический журнал ревизий харденинга по ГОСТ Р 34.11-2012.

Модуль связывает каждую ревизию конфигурации в неизменяемую цепочку
хешей «Стрибог-256» и управляет транзакционным применением патчей с
автоматическим откатом за ``< 8 секунд`` при сбое любой из трёх проверок
живучести (SSH ``22/tcp``, LAPP ``HTTP 200 OK``, PostgreSQL Ping).

Принципиальное решение по криптографии
--------------------------------------
ГОСТ Р 34.11-2012 реализуется эталонной библиотекой ``gostcrypto``
(``gosthash.new("streebog256", ...)``), а не самописным кодом: ручная
реализация 12-раундовой сети Миягучи — Пренеля с таблицами ``π``/``τ`` и
матрицей линейного преобразования ``L`` слишком легко даёт «похожий, но
неверный» результат, который невозможно заметить без эталонных векторов.

Модуль **намеренно не имеет** «запасной» реализации: если библиотека
недоступна, выбрасывается :class:`StreebogUnavailableError`. Тихий переход
на другой алгоритм разорвал бы цепочку ревизий при смене окружения —
именно это и происходило в исходном прототипе.

Корректность реализации контролируется тестами на официальных векторах
ГОСТ Р 34.11-2012 (RFC 6986): ``H256(M1)`` и ``H256("")``.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

#: Допустимые состояния транзакции ревизии.
STATUS_PENDING = "PENDING"
STATUS_COMMITTED = "COMMITTED"
STATUS_ROLLED_BACK = "ROLLED_BACK"
VALID_STATUSES: frozenset[str] = frozenset(
    {STATUS_PENDING, STATUS_COMMITTED, STATUS_ROLLED_BACK}
)

#: Домен разделения для хеширования цепочки (защита от cross-protocol атак).
CHAIN_DOMAIN = "B3-HARDENING-LEDGER-v1"

#: Генеральный (нулевой) хеш цепочки.
GENESIS_HASH = "0" * 64


class StreebogUnavailableError(RuntimeError):
    """Библиотека ГОСТ Р 34.11-2012 недоступна в текущем окружении."""


def _load_gosthash() -> Any:
    """Импортирует эталонную реализацию ГОСТ Р 34.11-2012.

    Raises:
        StreebogUnavailableError: если пакет ``gostcrypto`` не установлен.
    """
    try:
        from gostcrypto import gosthash  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise StreebogUnavailableError(
            "Для журнала ревизий требуется пакет gostcrypto "
            "(pip install gostcrypto). Запасная реализация намеренно "
            "отсутствует: подмена алгоритма разрывает цепочку хешей."
        ) from exc
    return gosthash


def is_streebog_available() -> bool:
    """Доступна ли эталонная реализация ГОСТ Р 34.11-2012."""
    try:
        _load_gosthash()
    except StreebogUnavailableError:
        return False
    return True


def streebog256_hex(data: bytes) -> str:
    """Вычисляет 256-битный дайджест «Стрибог-256» по ГОСТ Р 34.11-2012.

    Args:
        data: произвольная последовательность байт.

    Returns:
        Строка из 64 шестнадцатеричных символов в нижнем регистре.

    Raises:
        StreebogUnavailableError: если библиотека ГОСТ недоступна.
    """
    gosthash = _load_gosthash()
    return gosthash.new("streebog256", data=data).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    """Канонизирует JSON: сортировка ключей, без пробелов, UTF-8."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _is_hex64(value: str) -> bool:
    """Проверяет, что строка является 64-символьным hex-дайджестом."""
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdef" for ch in value.lower()
    )


@dataclass
class LedgerRevisionEntry:
    """Одна ревизия неизменяемого журнала харденинга."""

    revision_seq: int
    tx_id: str
    target_host: str
    created_at_utc: str
    merkle_root_before: str
    merkle_root_after: str
    patch_hash_gost: str
    prev_chain_hash: str
    chain_hash_gost: str
    status: str
    rollback_duration_ms: int | None
    patch_bundle: dict[str, Any] = field(default_factory=dict)

    @property
    def is_committed(self) -> bool:
        """Зафиксирована ли ревизия без отката."""
        return self.status == STATUS_COMMITTED

    @property
    def is_rolled_back(self) -> bool:
        """Была ли ревизия откачена сторожевым таймером."""
        return self.status == STATUS_ROLLED_BACK

    def to_dict(self) -> dict[str, Any]:
        """Сериализация ревизии в словарь (для JSONB и JSONL-выгрузки)."""
        return asdict(self)


class StreebogRollbackLedger:
    """Неизменяемый журнал ревизий и транзакционный исполнитель.

    Журнал хранит цепочку ревизий, в которой каждая запись ссылается на
    хеш предыдущей. Любая модификация исторической записи или разрыв
    цепочки обнаруживаются :meth:`verify_ledger_integrity`.
    """

    GENESIS_HASH: str = GENESIS_HASH

    def __init__(self) -> None:
        self._entries: list[LedgerRevisionEntry] = []
        self._tx_ids: set[str] = set()

    @property
    def entries(self) -> list[LedgerRevisionEntry]:
        """Копия списка ревизий в порядке добавления."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Хеширование цепочки
    # ------------------------------------------------------------------
    @staticmethod
    def compute_chain_hash(
        prev_chain_hash: str,
        tx_id: str,
        merkle_before: str,
        merkle_after: str,
        patch_hash_gost: str,
    ) -> str:
        """Вычисляет хеш ревизии «Стрибог-256» с привязкой к предыдущей.

        Поля кодируются каноническим JSON с доменом разделения, поэтому
        хеш не зависит от порядка аргументов и не допускает склейки
        значений через разделитель.
        """
        material = {
            "domain": CHAIN_DOMAIN,
            "prev": prev_chain_hash,
            "tx_id": tx_id,
            "merkle_before": merkle_before,
            "merkle_after": merkle_after,
            "patch_hash_gost": patch_hash_gost,
        }
        return streebog256_hex(_canonical_json(material))

    # ------------------------------------------------------------------
    # Запись ревизий
    # ------------------------------------------------------------------
    def record_revision(
        self,
        tx_id: str,
        target_host: str,
        merkle_root_before: str,
        merkle_root_after: str,
        patch_bundle: dict[str, Any],
        status: str = STATUS_PENDING,
    ) -> LedgerRevisionEntry:
        """Добавляет ревизию в журнал и возвращает созданную запись.

        Args:
            tx_id: уникальный идентификатор транзакции.
            target_host: FQDN или инвентарное имя защищаемого узла.
            merkle_root_before: корень дерева Меркла до применения патча.
            merkle_root_after: корень дерева Меркла после применения патча.
            patch_bundle: канонизируемый набор изменений конфигурации.
            status: начальный статус транзакции.

        Raises:
            ValueError: при пустом ``tx_id``, дубликате ``tx_id``,
                некорректном статусе или неверном формате хешей.
        """
        if not tx_id:
            raise ValueError("tx_id не может быть пустым")
        if tx_id in self._tx_ids:
            raise ValueError(f"дубликат tx_id: {tx_id}")
        if status not in VALID_STATUSES:
            raise ValueError(f"недопустимый статус: {status}")
        for name, value in (
            ("merkle_root_before", merkle_root_before),
            ("merkle_root_after", merkle_root_after),
        ):
            if not _is_hex64(value):
                raise ValueError(f"{name} должен быть 64-символьным hex-дайджестом")

        prev_hash = self._entries[-1].chain_hash_gost if self._entries else self.GENESIS_HASH
        patch_hash = streebog256_hex(_canonical_json(patch_bundle))
        chain_hash = self.compute_chain_hash(
            prev_chain_hash=prev_hash,
            tx_id=tx_id,
            merkle_before=merkle_root_before,
            merkle_after=merkle_root_after,
            patch_hash_gost=patch_hash,
        )

        entry = LedgerRevisionEntry(
            revision_seq=len(self._entries) + 1,
            tx_id=tx_id,
            target_host=target_host,
            created_at_utc=datetime.now(timezone.utc).isoformat(),
            merkle_root_before=merkle_root_before,
            merkle_root_after=merkle_root_after,
            patch_hash_gost=patch_hash,
            prev_chain_hash=prev_hash,
            chain_hash_gost=chain_hash,
            status=status,
            rollback_duration_ms=None,
            patch_bundle=patch_bundle,
        )
        self._entries.append(entry)
        self._tx_ids.add(tx_id)
        return entry

    # ------------------------------------------------------------------
    # Проверка целостности
    # ------------------------------------------------------------------
    def verify_ledger_integrity(self) -> tuple[bool, str]:
        """Проверяет непрерывность и целостность всей цепочки ревизий.

        Returns:
            Кортеж ``(успех, сообщение)``. При обнаружении разрыва или
            подмены возвращается ``(False, описание)``.
        """
        expected_prev = self.GENESIS_HASH
        for idx, entry in enumerate(self._entries, start=1):
            if entry.revision_seq != idx:
                return False, f"Revision #{idx}: нарушена нумерация revision_seq"
            if entry.prev_chain_hash != expected_prev:
                return (
                    False,
                    f"Chain broken at revision #{idx} ({entry.tx_id}): "
                    "prev_chain_hash mismatch",
                )
            recalc_patch_hash = streebog256_hex(_canonical_json(entry.patch_bundle))
            if recalc_patch_hash != entry.patch_hash_gost:
                return (
                    False,
                    f"Tampered patch_bundle detected at revision #{idx} ({entry.tx_id})",
                )
            recalc_chain = self.compute_chain_hash(
                prev_chain_hash=entry.prev_chain_hash,
                tx_id=entry.tx_id,
                merkle_before=entry.merkle_root_before,
                merkle_after=entry.merkle_root_after,
                patch_hash_gost=recalc_patch_hash,
            )
            if recalc_chain != entry.chain_hash_gost:
                return (
                    False,
                    f"Tampered chain_hash_gost at revision #{idx} ({entry.tx_id})",
                )
            expected_prev = entry.chain_hash_gost
        return True, f"VERIFIED ({len(self._entries)} revisions intact)"

    # ------------------------------------------------------------------
    # Транзакционное применение с Dead-Man's Switch
    # ------------------------------------------------------------------
    def execute_transactional_hardening(
        self,
        tx_id: str,
        target_host: str,
        merkle_before: str,
        merkle_after: str,
        patch_bundle: dict[str, Any],
        apply_fn: Callable[[], None],
        healthcheck_fn: Callable[[], bool],
        rollback_fn: Callable[[], None],
        watchdog_timeout_sec: float = 8.0,
    ) -> LedgerRevisionEntry:
        """Атомарно применяет патч с контролем живучести и откатом.

        Транзакция фиксируется как ``COMMITTED`` только если применение и
        проверка живучести уложились в окно ``watchdog_timeout_sec``.
        Иначе вызывается ``rollback_fn`` и статус становится
        ``ROLLED_BACK``.

        Args:
            apply_fn: применение патча на целевом узле.
            healthcheck_fn: проверка живучести (SSH + HTTP + DB Ping).
            rollback_fn: восстановление снимка конфигурации.
            watchdog_timeout_sec: окно сторожевого таймера, секунды.

        Returns:
            Запись журнала с итоговым статусом.
        """
        entry = self.record_revision(
            tx_id=tx_id,
            target_host=target_host,
            merkle_root_before=merkle_before,
            merkle_root_after=merkle_after,
            patch_bundle=patch_bundle,
            status=STATUS_PENDING,
        )

        started = time.monotonic()
        healthy = False
        try:
            apply_fn()
            healthy = bool(healthcheck_fn())
        except Exception:  # noqa: BLE001 - любой сбой применения = откат
            healthy = False
        elapsed = time.monotonic() - started

        if healthy and elapsed <= watchdog_timeout_sec:
            entry.status = STATUS_COMMITTED
            entry.rollback_duration_ms = 0
            return entry

        rollback_started = time.monotonic()
        try:
            rollback_fn()
        finally:
            elapsed_rollback = time.monotonic() - rollback_started
        entry.status = STATUS_ROLLED_BACK
        entry.rollback_duration_ms = max(1, int(elapsed_rollback * 1000))
        return entry

    # ------------------------------------------------------------------
    # Экспорт
    # ------------------------------------------------------------------
    def export_jsonl(self, target: Path | str) -> Path:
        """Выгружает журнал в JSONL для загрузки в PostgreSQL (JSONB)."""
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for entry in self._entries:
                handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return path

    def append_external_entries(self, entries: Iterable[dict[str, Any]]) -> None:
        """Восстанавливает журнал из выгрузки (например, после перезапуска)."""
        for raw in entries:
            entry = LedgerRevisionEntry(**raw)
            if entry.status not in VALID_STATUSES:
                raise ValueError(f"недопустимый статус во внешней записи: {entry.status}")
            self._entries.append(entry)
            self._tx_ids.add(entry.tx_id)

    def chain_hashes(self) -> Sequence[str]:
        """Возвращает последовательность хешей цепочки для сверки с БД."""
        return [entry.chain_hash_gost for entry in self._entries]
