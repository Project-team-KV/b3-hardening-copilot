"""Тесты журнала ревизий «Стрибог-256» и транзакционного отката.

Проверяют:
    * соответствие ГОСТ Р 34.11-2012 на официальных векторах RFC 6986;
    * отсутствие «тихого» fallback при недоступности ГОСТ-библиотеки;
    * целостность цепочки и обнаружение подмены;
    * сценарии COMMITTED / ROLLED_BACK сторожевого таймера.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from crypto import streebog_rollback_ledger as ledger_mod
from crypto.streebog_rollback_ledger import (
    GENESIS_HASH,
    STATUS_COMMITTED,
    STATUS_PENDING,
    STATUS_ROLLED_BACK,
    LedgerRevisionEntry,
    StreebogRollbackLedger,
    StreebogUnavailableError,
    is_streebog_available,
    streebog256_hex,
)

# Официальные тест-векторы ГОСТ Р 34.11-2012 (RFC 6986, Приложение А).
M1 = b"012345678901234567890123456789012345678901234567890123456789012"
H256_M1 = "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
H256_EMPTY = "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"

ROOT_A = "a" * 64
ROOT_B = "b" * 64


# ---------------------------------------------------------------------------
# ГОСТ Р 34.11-2012
# ---------------------------------------------------------------------------
class TestStreebogVectors:
    """Соответствие эталонным векторам стандарта."""

    def test_official_vector_m1(self):
        assert streebog256_hex(M1) == H256_M1

    def test_official_vector_empty(self):
        assert streebog256_hex(b"") == H256_EMPTY

    def test_digest_is_64_hex_chars(self):
        digest = streebog256_hex(b"hello")
        assert len(digest) == 64
        assert all(ch in "0123456789abcdef" for ch in digest)

    def test_digest_is_deterministic(self):
        assert streebog256_hex(b"same") == streebog256_hex(b"same")

    def test_avalanche_on_single_bit_change(self):
        assert streebog256_hex(b"patch") != streebog256_hex(b"patcb")

    def test_library_available(self):
        assert is_streebog_available() is True


class TestNoSilentFallback:
    """Недоступность ГОСТ-библиотеки должна приводить к явной ошибке."""

    def test_raises_when_library_missing(self, monkeypatch):
        def _boom():
            raise StreebogUnavailableError("нет gostcrypto")

        monkeypatch.setattr(ledger_mod, "_load_gosthash", _boom)
        with pytest.raises(StreebogUnavailableError):
            ledger_mod.streebog256_hex(b"data")

    def test_is_available_reports_false(self, monkeypatch):
        def _boom():
            raise StreebogUnavailableError("нет gostcrypto")

        monkeypatch.setattr(ledger_mod, "_load_gosthash", _boom)
        assert ledger_mod.is_streebog_available() is False


# ---------------------------------------------------------------------------
# Хеширование цепочки
# ---------------------------------------------------------------------------
class TestChainHash:
    """Детерминированность и чувствительность хеша цепочки."""

    def test_deterministic(self):
        args = dict(
            prev_chain_hash=GENESIS_HASH,
            tx_id="tx_1",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_hash_gost="c" * 64,
        )
        assert StreebogRollbackLedger.compute_chain_hash(**args) == (
            StreebogRollbackLedger.compute_chain_hash(**args)
        )

    @pytest.mark.parametrize(
        "field, value",
        [
            ("tx_id", "tx_2"),
            ("merkle_after", "d" * 64),
            ("prev_chain_hash", "e" * 64),
            ("patch_hash_gost", "f" * 64),
        ],
    )
    def test_sensitive_to_each_field(self, field, value):
        base = dict(
            prev_chain_hash=GENESIS_HASH,
            tx_id="tx_1",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_hash_gost="c" * 64,
        )
        changed = dict(base, **{field: value})
        assert StreebogRollbackLedger.compute_chain_hash(
            **base
        ) != StreebogRollbackLedger.compute_chain_hash(**changed)

    def test_no_delimiter_collision(self):
        """Склейка через разделитель не должна давать коллизий."""
        a = StreebogRollbackLedger.compute_chain_hash(
            prev_chain_hash=GENESIS_HASH,
            tx_id="a|b",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_hash_gost="c" * 64,
        )
        b = StreebogRollbackLedger.compute_chain_hash(
            prev_chain_hash=GENESIS_HASH,
            tx_id="a",
            merkle_before="b",
            merkle_after=ROOT_B,
            patch_hash_gost="c" * 64,
        )
        assert a != b


# ---------------------------------------------------------------------------
# Запись ревизий
# ---------------------------------------------------------------------------
class TestRecordRevision:
    """Формирование записей журнала."""

    def test_first_revision_links_to_genesis(self):
        ledger = StreebogRollbackLedger()
        entry = ledger.record_revision("tx_1", "vm-302", ROOT_A, ROOT_B, {"ssh": "x"})
        assert entry.revision_seq == 1
        assert entry.prev_chain_hash == GENESIS_HASH
        assert entry.status == STATUS_PENDING

    def test_sequence_and_linking(self):
        ledger = StreebogRollbackLedger()
        first = ledger.record_revision("tx_1", "vm-302", ROOT_A, ROOT_B, {"a": 1})
        second = ledger.record_revision("tx_2", "vm-302", ROOT_B, ROOT_A, {"b": 2})
        assert second.revision_seq == 2
        assert second.prev_chain_hash == first.chain_hash_gost

    def test_entries_property_returns_copy(self):
        ledger = StreebogRollbackLedger()
        ledger.record_revision("tx_1", "host", ROOT_A, ROOT_B, {})
        snapshot = ledger.entries
        snapshot.clear()
        assert len(ledger) == 1

    def test_duplicate_tx_id_rejected(self):
        ledger = StreebogRollbackLedger()
        ledger.record_revision("tx_1", "host", ROOT_A, ROOT_B, {})
        with pytest.raises(ValueError, match="дубликат tx_id"):
            ledger.record_revision("tx_1", "host", ROOT_A, ROOT_B, {})

    def test_empty_tx_id_rejected(self):
        ledger = StreebogRollbackLedger()
        with pytest.raises(ValueError, match="tx_id"):
            ledger.record_revision("", "host", ROOT_A, ROOT_B, {})

    def test_invalid_status_rejected(self):
        ledger = StreebogRollbackLedger()
        with pytest.raises(ValueError, match="статус"):
            ledger.record_revision("tx_1", "host", ROOT_A, ROOT_B, {}, status="DONE")

    def test_invalid_merkle_root_rejected(self):
        ledger = StreebogRollbackLedger()
        with pytest.raises(ValueError, match="merkle_root_before"):
            ledger.record_revision("tx_1", "host", "not-a-hash", ROOT_B, {})

    @pytest.mark.parametrize("bad_root", ["A" * 64, "a" * 63, "a" * 65, "z" * 64])
    def test_non_lowercase_or_wrong_length_root_rejected(self, bad_root):
        """Верхний регистр отвергается: ограничение БД требует нижний."""
        ledger = StreebogRollbackLedger()
        with pytest.raises(ValueError, match="hex"):
            ledger.record_revision("tx_1", "host", bad_root, ROOT_B, {})

    def test_patch_bundle_canonicalisation(self):
        """Порядок ключей не влияет на хеш патча."""
        one = StreebogRollbackLedger()
        two = StreebogRollbackLedger()
        a = one.record_revision("tx_1", "h", ROOT_A, ROOT_B, {"x": 1, "y": 2})
        b = two.record_revision("tx_1", "h", ROOT_A, ROOT_B, {"y": 2, "x": 1})
        assert a.patch_hash_gost == b.patch_hash_gost
        assert a.chain_hash_gost == b.chain_hash_gost


# ---------------------------------------------------------------------------
# Целостность журнала
# ---------------------------------------------------------------------------
class TestLedgerIntegrity:
    """Обнаружение подмены и разрыва цепочки."""

    def _ledger(self) -> StreebogRollbackLedger:
        ledger = StreebogRollbackLedger()
        ledger.record_revision("tx_1", "vm-302", ROOT_A, ROOT_B, {"sshd": "PermitRootLogin no"})
        ledger.record_revision("tx_2", "vm-302", ROOT_B, ROOT_A, {"sysctl": "rp_filter=1"})
        return ledger

    def test_empty_ledger_verified(self):
        ok, message = StreebogRollbackLedger().verify_ledger_integrity()
        assert ok is True
        assert "0 revisions" in message

    def test_intact_ledger_verified(self):
        ok, message = self._ledger().verify_ledger_integrity()
        assert ok is True
        assert "VERIFIED (2 revisions intact)" == message

    def test_tampered_patch_bundle_detected(self):
        ledger = self._ledger()
        ledger.entries[0].patch_bundle["sshd"] = "PermitRootLogin yes"
        ok, message = ledger.verify_ledger_integrity()
        assert ok is False
        assert "Tampered patch_bundle" in message

    def test_tampered_chain_hash_detected(self):
        ledger = self._ledger()
        ledger.entries[1].chain_hash_gost = "0" * 64
        ok, message = ledger.verify_ledger_integrity()
        assert ok is False
        assert "prev_chain_hash mismatch" in message or "Tampered chain_hash" in message

    def test_broken_prev_link_detected(self):
        ledger = self._ledger()
        ledger.entries[1].prev_chain_hash = "1" * 64
        ok, message = ledger.verify_ledger_integrity()
        assert ok is False
        assert "Chain broken at revision #2" in message

    def test_broken_sequence_detected(self):
        ledger = self._ledger()
        ledger.entries[1].revision_seq = 7
        ok, message = ledger.verify_ledger_integrity()
        assert ok is False
        assert "нумерация" in message


# ---------------------------------------------------------------------------
# Транзакционный откат
# ---------------------------------------------------------------------------
class TestTransactionalHardening:
    """Сценарии COMMITTED и ROLLED_BACK."""

    def test_committed_on_healthy_apply(self):
        ledger = StreebogRollbackLedger()
        called = {"apply": 0, "rollback": 0}

        def apply_fn():
            called["apply"] += 1

        def rollback_fn():
            called["rollback"] += 1

        entry = ledger.execute_transactional_hardening(
            tx_id="tx_ok",
            target_host="vm-302",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_bundle={"sshd": "ok"},
            apply_fn=apply_fn,
            healthcheck_fn=lambda: True,
            rollback_fn=rollback_fn,
        )
        assert entry.status == STATUS_COMMITTED
        assert entry.rollback_duration_ms == 0
        assert called == {"apply": 1, "rollback": 0}
        assert ledger.verify_ledger_integrity()[0] is True

    def test_rollback_when_healthcheck_fails(self):
        ledger = StreebogRollbackLedger()
        called = {"rollback": 0}

        def rollback_fn():
            called["rollback"] += 1

        entry = ledger.execute_transactional_hardening(
            tx_id="tx_bad",
            target_host="vm-302",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_bundle={"sshd": "bad"},
            apply_fn=lambda: None,
            healthcheck_fn=lambda: False,
            rollback_fn=rollback_fn,
        )
        assert entry.status == STATUS_ROLLED_BACK
        assert entry.rollback_duration_ms is not None
        assert entry.rollback_duration_ms >= 1
        assert called["rollback"] == 1

    def test_rollback_when_apply_raises(self):
        ledger = StreebogRollbackLedger()

        def apply_fn():
            raise RuntimeError("nftables apply failed")

        entry = ledger.execute_transactional_hardening(
            tx_id="tx_crash",
            target_host="vm-302",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_bundle={},
            apply_fn=apply_fn,
            healthcheck_fn=lambda: True,
            rollback_fn=lambda: None,
        )
        assert entry.status == STATUS_ROLLED_BACK

    def test_rollback_when_watchdog_expires(self):
        ledger = StreebogRollbackLedger()

        def slow_apply():
            time.sleep(0.05)

        entry = ledger.execute_transactional_hardening(
            tx_id="tx_slow",
            target_host="vm-302",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_bundle={},
            apply_fn=slow_apply,
            healthcheck_fn=lambda: True,
            rollback_fn=lambda: None,
            watchdog_timeout_sec=0.01,
        )
        assert entry.status == STATUS_ROLLED_BACK

    def test_rollback_duration_measured(self):
        ledger = StreebogRollbackLedger()

        def slow_rollback():
            # Заметно больше разрешения системного таймера Windows (~15,6 мс),
            # иначе замер получается нестабильным.
            time.sleep(0.08)

        entry = ledger.execute_transactional_hardening(
            tx_id="tx_rb",
            target_host="vm-302",
            merkle_before=ROOT_A,
            merkle_after=ROOT_B,
            patch_bundle={},
            apply_fn=lambda: None,
            healthcheck_fn=lambda: False,
            rollback_fn=slow_rollback,
        )
        assert entry.rollback_duration_ms is not None
        assert entry.rollback_duration_ms >= 50


# ---------------------------------------------------------------------------
# Экспорт и восстановление
# ---------------------------------------------------------------------------
class TestExport:
    """JSONL-выгрузка для загрузки в PostgreSQL."""

    def test_export_jsonl(self, workdir):
        ledger = StreebogRollbackLedger()
        ledger.record_revision("tx_1", "vm-302", ROOT_A, ROOT_B, {"a": 1})
        ledger.record_revision("tx_2", "vm-303", ROOT_B, ROOT_A, {"b": 2})
        path = ledger.export_jsonl(workdir / "ledger.jsonl")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["tx_id"] == "tx_1"
        assert first["chain_hash_gost"] == ledger.entries[0].chain_hash_gost

    def test_roundtrip_restore(self, workdir):
        source = StreebogRollbackLedger()
        source.record_revision("tx_1", "vm-302", ROOT_A, ROOT_B, {"a": 1})
        source.record_revision("tx_2", "vm-302", ROOT_B, ROOT_A, {"b": 2})
        path = source.export_jsonl(workdir / "ledger.jsonl")

        restored = StreebogRollbackLedger()
        restored.append_external_entries(
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        )
        assert restored.chain_hashes() == source.chain_hashes()
        assert restored.verify_ledger_integrity()[0] is True

    def test_entry_to_dict(self):
        entry = LedgerRevisionEntry(
            revision_seq=1,
            tx_id="tx",
            target_host="host",
            created_at_utc="2026-11-03T00:00:00+00:00",
            merkle_root_before=ROOT_A,
            merkle_root_after=ROOT_B,
            patch_hash_gost="c" * 64,
            prev_chain_hash=GENESIS_HASH,
            chain_hash_gost="d" * 64,
            status=STATUS_COMMITTED,
            rollback_duration_ms=0,
            patch_bundle={"x": 1},
        )
        payload = entry.to_dict()
        assert payload["status"] == STATUS_COMMITTED
        assert entry.is_committed is True
        assert entry.is_rolled_back is False
