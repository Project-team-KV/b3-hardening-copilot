-- migrations/001_hardening_ledger.sql
-- Владелец схемы: Вебер Александр Александрович (@mbr_DIGMA_PRO_Sprint), Команда Б3
-- Неизменяемый криптографический журнал ревизий конфигурации по ГОСТ Р 34.11-2012
-- («Стрибог-256») и ГОСТ Р 59548-2022.
--
-- Применение:  psql -U secops -d hardening -f migrations/001_hardening_ledger.sql

BEGIN;

CREATE TABLE IF NOT EXISTS hardening_revisions_ledger (
    revision_seq        BIGSERIAL PRIMARY KEY,
    tx_id               VARCHAR(64)  NOT NULL UNIQUE,
    target_host         VARCHAR(128) NOT NULL,
    created_at_utc      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Корни дерева Меркла состояния узла до и после применения патча.
    merkle_root_before  CHAR(64)     NOT NULL,
    merkle_root_after   CHAR(64)     NOT NULL,

    -- Хеши ГОСТ Р 34.11-2012 («Стрибог-256»).
    patch_hash_gost     CHAR(64)     NOT NULL,
    prev_chain_hash     CHAR(64)     NOT NULL,
    chain_hash_gost     CHAR(64)     NOT NULL UNIQUE,

    status              VARCHAR(32)  NOT NULL
                        CHECK (status IN ('PENDING', 'COMMITTED', 'ROLLED_BACK')),
    rollback_duration_ms INTEGER,
    patch_bundle_json   JSONB        NOT NULL,

    -- Формат дайджестов: 64 шестнадцатеричных символа в нижнем регистре.
    CONSTRAINT chk_merkle_before_hex
        CHECK (merkle_root_before ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_merkle_after_hex
        CHECK (merkle_root_after  ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_patch_hash_hex
        CHECK (patch_hash_gost    ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_prev_chain_hex
        CHECK (prev_chain_hash    ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_chain_hash_hex
        CHECK (chain_hash_gost    ~ '^[0-9a-f]{64}$'),

    -- Откат обязан фиксировать измеренную длительность, фиксация — нет.
    CONSTRAINT chk_rollback_duration
        CHECK (
            (status = 'ROLLED_BACK' AND rollback_duration_ms IS NOT NULL)
            OR (status <> 'ROLLED_BACK')
        )
);

COMMENT ON TABLE hardening_revisions_ledger IS
    'Неизменяемый журнал ревизий харденинга (ГОСТ Р 34.11-2012, ГОСТ Р 59548-2022)';
COMMENT ON COLUMN hardening_revisions_ledger.chain_hash_gost IS
    'H(prev_chain_hash || tx_id || merkle_before || merkle_after || patch_hash_gost)';
COMMENT ON COLUMN hardening_revisions_ledger.rollback_duration_ms IS
    'Измеренное время автоматического отката Dead-Man''s Switch, мс';

CREATE INDEX IF NOT EXISTS idx_hardening_ledger_host_seq
    ON hardening_revisions_ledger (target_host, revision_seq DESC);

CREATE INDEX IF NOT EXISTS idx_hardening_ledger_status
    ON hardening_revisions_ledger (status)
    WHERE status <> 'COMMITTED';

-- Триггер защиты от удаления и подмены исторических криптографических
-- полей (ГОСТ Р 59548-2022). Разрешено менять только status и
-- rollback_duration_ms — это единственные поля, которые транзакция
-- обновляет после завершения сторожевого окна.
CREATE OR REPLACE FUNCTION prevent_ledger_tampering()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'GOST R 59548-2022 VIOLATION: DELETE on hardening_revisions_ledger is strictly forbidden';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.chain_hash_gost    <> NEW.chain_hash_gost
           OR OLD.prev_chain_hash <> NEW.prev_chain_hash
           OR OLD.patch_hash_gost <> NEW.patch_hash_gost
           OR OLD.merkle_root_before <> NEW.merkle_root_before
           OR OLD.merkle_root_after  <> NEW.merkle_root_after
           OR OLD.tx_id           <> NEW.tx_id
           OR OLD.target_host     <> NEW.target_host
           OR OLD.revision_seq    <> NEW.revision_seq THEN
            RAISE EXCEPTION
                'GOST R 59548-2022 VIOLATION: cryptographic chain fields in hardening_revisions_ledger are immutable';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_immutable_hardening_ledger ON hardening_revisions_ledger;
CREATE TRIGGER trg_immutable_hardening_ledger
    BEFORE UPDATE OR DELETE ON hardening_revisions_ledger
    FOR EACH ROW EXECUTE FUNCTION prevent_ledger_tampering();

-- Представление для отчётов: последняя ревизия по каждому узлу.
CREATE OR REPLACE VIEW v_hardening_ledger_head AS
SELECT DISTINCT ON (target_host)
       target_host,
       revision_seq,
       tx_id,
       created_at_utc,
       chain_hash_gost,
       status
FROM hardening_revisions_ledger
ORDER BY target_host, revision_seq DESC;

COMMIT;
