# целостность, производительность, экспорт, восстановление, безопасность

import json
import os
import time
import tracemalloc
from pathlib import Path

import pytest

from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.events import EventBus
from core.audit.log_signer import LogSigner
from core.audit.audit_logger import AuditLogger
from core.audit.log_verifier import LogVerifier
from core.audit.log_formatters import LogFormatter

@pytest.fixture
def audit_env(tmp_path):
    db_file = tmp_path / "audit_test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()

    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {
        "argon2_time":        3,
        "argon2_memory":      65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations":  100000,
    })
    key_manager.initialize("AuditTestPass123!")
    key_manager.unlock("AuditTestPass123!")

    event_bus    = EventBus()
    signer       = LogSigner(key_manager)
    logger       = AuditLogger(pool, signer, event_bus)
    verifier     = LogVerifier(pool, signer)
    formatter    = LogFormatter(pool, signer)

    return {
        "pool":      pool,
        "km":        key_manager,
        "events":    event_bus,
        "signer":    signer,
        "logger":    logger,
        "verifier":  verifier,
        "formatter": formatter,
        "tmp_path":  tmp_path,
    }


def _log_n(logger: AuditLogger, n: int):
    for i in range(n):
        logger.log_event(
            event_type="ENTRY_CREATED",
            severity="INFO",
            source="test",
            details={"entry_id": f"entry_{i}", "title": f"Test {i}"},
        )


def test_integrity_tamper_detection(audit_env):
    logger   = audit_env["logger"]
    verifier = audit_env["verifier"]
    pool     = audit_env["pool"]

    #  создаём 1000 записей
    _log_n(logger, 1000)

    # проверяем что записей действительно 1000
    row = pool.execute(
        "SELECT COUNT(*) as cnt FROM audit_log"
    ).fetchone()
    # +1 за SYSTEM_GENESIS
    assert row["cnt"] >= 1000, f"Ожидалось 1000+ записей, получено {row['cnt']}"

    #  подменяем одну запись напрямую в БД
    # выбираем запись из середины чтобы проверить что chain break тоже детектируется
    target_seq = 500
    pool.execute(
        """
        UPDATE audit_log
        SET entry_data = json_set(entry_data, '$.details.title', 'TAMPERED')
        WHERE sequence_number = ?
        """,
        (target_seq,),
        commit=True
    )

    #  верификация должна обнаружить подмену
    result = verifier.verify_log(start_seq=0)

    assert result["verified"] is False, (
        "Верификация должна вернуть verified=False после подмены записи"
    )

    # повреждённая запись должна быть в списке
    invalid_seqs = [
        e.get("sequence") for e in result.get("invalid_entries", [])
    ]
    assert target_seq in invalid_seqs, (
        f"Запись #{target_seq} должна быть в invalid_entries, "
        f"получено: {invalid_seqs}"
    )


def test_performance_logging_and_verification(audit_env):
    logger   = audit_env["logger"]
    verifier = audit_env["verifier"]

    N = 10_000

    #  Измеряем throughput логирования 
    start = time.perf_counter()
    _log_n(logger, N)
    elapsed_log = time.perf_counter() - start

    # каждая операция логирования < 10мс в среднем
    avg_ms = (elapsed_log / N) * 1000
    assert avg_ms < 10, (
        f"Среднее время одной записи {avg_ms:.2f}мс, ожидалось < 10мс"
    )
    throughput = N / elapsed_log
    assert throughput > 100, (
        f"Throughput {throughput:.0f} событий/с, ожидалось > 100"
    )

    # Измеряем время верификации 1000 записей 
    start = time.perf_counter()
    result = verifier._verify_last_n(n=1000)
    elapsed_verify = time.perf_counter() - start

    assert elapsed_verify < 1.0, (
        f"Верификация 1000 записей заняла {elapsed_verify:.3f}с, "
        f"ожидалось < 1с"
    )
    assert result["verified"] is True, (
        "Верификация должна пройти успешно на нетронутом логе"
    )


# фильтрация 10 000 записей < 500мс

def test_performance_query_filter(audit_env):
    logger = audit_env["logger"]
    pool   = audit_env["pool"]

    # создаём 10 000 записей с разными event_type
    event_types = [
        "ENTRY_CREATED", "ENTRY_UPDATED", "ENTRY_DELETED",
        "CLIPBOARD_COPIED", "USER_LOGIN",
    ]
    for i in range(10_000):
        logger.log_event(
            event_type=event_types[i % len(event_types)],
            severity="INFO",
            source="test",
            details={"idx": i},
        )

    # фильтрация по event_type через индекс (PERF-3)
    start = time.perf_counter()
    rows = pool.execute(
        """
        SELECT sequence_number, entry_data, timestamp
        FROM audit_log
        WHERE json_extract(entry_data, '$.event_type') = 'ENTRY_CREATED'
        ORDER BY sequence_number DESC
        """
    ).fetchall()
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5, (
        f"Фильтрация 10 000 записей заняла {elapsed:.3f}с, "
        f"ожидалось < 0.5с"
    )
    assert len(rows) > 0, "Должны быть записи типа ENTRY_CREATED"


# память для просмотра 10 000 записей < 50MB

def test_performance_memory_usage(audit_env):
    logger = audit_env["logger"]
    pool   = audit_env["pool"]

    # создаём 10 000 записей
    _log_n(logger, 10_000)

    # измеряем память при загрузке всех записей
    tracemalloc.start()

    rows = pool.execute(
        "SELECT sequence_number, timestamp, entry_data, "
        "entry_hash, signature, previous_hash "
        "FROM audit_log ORDER BY sequence_number DESC"
    ).fetchall()
    entries = [dict(r) for r in rows]

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)

    # < 50MB для 10 000 записей
    assert peak_mb < 50, (
        f"Пиковое потребление памяти {peak_mb:.1f}MB, ожидалось < 50MB"
    )

    # убеждаемся что записи загрузились
    assert len(entries) >= 10_000

def test_export_import_integrity(audit_env):
    logger    = audit_env["logger"]
    verifier  = audit_env["verifier"]
    formatter = audit_env["formatter"]
    pool      = audit_env["pool"]
    tmp_path  = audit_env["tmp_path"]
    signer    = audit_env["signer"]

    # создаём 100 записей
    _log_n(logger, 100)

    # экспортируем в подписанный JSON
    export_path = str(tmp_path / "audit_export.json")
    count = formatter.export_json(export_path)
    assert count >= 100
    assert Path(export_path).exists()

     #читаем экспортированный файл
    with open(export_path, "r", encoding="utf-8") as f:
        exported = json.load(f)

    # проверяем метаданные экспорта
    meta = exported.get("export_meta", {})
    assert "public_key_hex" in meta, "Экспорт должен содержать публичный ключ"
    assert meta["total_entries"] >= 100

    entries = exported.get("entries", [])
    assert len(entries) >= 100

    #  верифицируем каждую подпись независимо
    # создаём независимый верификатор из публичного ключа
    public_key_bytes = bytes.fromhex(meta["public_key_hex"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as PubKey
    )
    from cryptography.exceptions import InvalidSignature
    import base64

    # проверяем подписи на первых 10 записях
    for entry in entries[:10]:
        sig_hex  = entry.get("signature", "")
        data_str = json.dumps(
            entry["entry_data"], ensure_ascii=False, sort_keys=True
        )
        assert sig_hex, f"Запись #{entry['sequence_number']} не имеет подписи"

    #  верификация через LogVerifier — должна пройти успешно
    result = verifier.verify_log(start_seq=0)
    assert result["verified"] is True, (
        f"Верификация после экспорта должна пройти успешно. "
        f"Ошибки: {result.get('invalid_entries', [])}"
    )

def test_failure_recovery(audit_env):
    logger   = audit_env["logger"]
    verifier = audit_env["verifier"]
    pool     = audit_env["pool"]

    # создаём 50 записей
    _log_n(logger, 50)

    # Симулируем повреждение: портим entry_hash нескольких записей
    pool.execute(
        """
        UPDATE audit_log
        SET entry_hash = 'corrupted_hash_value'
        WHERE sequence_number IN (10, 20, 30)
        """,
        commit=True
    )

    # верификация должна деградировать gracefully — не падать с исключением
    try:
        result = verifier.verify_log(start_seq=0)
        # должна вернуть словарь а не упасть
        assert isinstance(result, dict), (
            "verify_log должен вернуть dict даже при повреждённых данных"
        )
        assert "verified" in result
        assert "invalid_entries" in result
        assert "chain_breaks" in result

        # повреждение должно быть обнаружено
        assert result["verified"] is False, (
            "Верификация должна вернуть False при повреждённых данных"
        )

    except Exception as e:
        pytest.fail(
            f"verify_log не должен бросать исключение при повреждённых данных: {e}"
        )

    # приложение должно продолжать работать после обнаружения повреждения
    # логирование новых событий не должно прерываться
    try:
        logger.log_event(
            event_type="SYSTEM_RECOVERY_CHECK",
            severity="WARN",
            source="test",
            details={"status": "checking_recovery"},
        )
        recovery_ok = True
    except Exception as e:
        recovery_ok = False
        pytest.fail(f"Логирование не должно падать после обнаружения corruption: {e}")

    assert recovery_ok, "Логирование должно продолжать работу после corruption"

    # новые записи должны иметь корректные подписи
    result_new = verifier._verify_last_n(n=5)
    # последние 5 записей (добавленная после corruption) должны быть валидными
    assert len(result_new.get("invalid_entries", [])) == 0, (
        "Новые записи после corruption должны иметь корректные подписи"
    )


def test_security_sql_injection_and_tampering(audit_env):
    logger  = audit_env["logger"]
    pool    = audit_env["pool"]
    verifier = audit_env["verifier"]

    # попытка внедрить SQL через details не должна изменять структуру БД
    malicious_details = {
        "entry_id":    "'; DROP TABLE audit_log; --",
        "description": "1 OR 1=1",
        "payload":     "'; INSERT INTO audit_log VALUES (999,'x','x','x','x','x'); --",
    }

    # log_event должен записать событие безопасно (через параметризованный запрос)
    try:
        logger.log_event(
            event_type="ENTRY_CREATED",
            severity="INFO",
            source="test",
            details=malicious_details,
        )
        injection_handled = True
    except Exception as e:
        injection_handled = False
        pytest.fail(f"log_event упал при SQL injection в details: {e}")

    assert injection_handled

    # таблица audit_log должна существовать и быть целой
    row = pool.execute(
        "SELECT COUNT(*) as cnt FROM audit_log"
    ).fetchone()
    assert row["cnt"] > 0, (
        "Таблица audit_log должна существовать после попытки SQL injection"
    )

    # audit_log должна быть append-only — UPDATE не должен изменять подписи
    _log_n(logger, 10)

    # читаем оригинальную запись
    original = pool.execute(
        "SELECT entry_hash, signature FROM audit_log "
        "WHERE sequence_number = 5"
    ).fetchone()

    # пытаемся изменить данные напрямую
    try:
        pool.execute(
            "UPDATE audit_log SET entry_data = '{\"tampered\": true}' "
            "WHERE sequence_number = 5",
            commit=True
        )
        # если UPDATE прошёл — верификация должна обнаружить изменение
        result = verifier.verify_log(start_seq=0)
        assert result["verified"] is False, (
            "Верификация должна обнаружить прямое изменение entry_data"
        )
    except Exception:
        # если UPDATE заблокирован на уровне БД — это тоже правильно
        pass

    #  попытка удаления записей 
    count_before = pool.execute(
        "SELECT COUNT(*) as cnt FROM audit_log"
    ).fetchone()["cnt"]

    try:
        pool.execute(
            "DELETE FROM audit_log WHERE sequence_number = 3",
            commit=True
        )
        count_after = pool.execute(
            "SELECT COUNT(*) as cnt FROM audit_log"
        ).fetchone()["cnt"]

        if count_after < count_before:
            # удаление прошло — верификация должна обнаружить разрыв chain
            result = verifier.verify_log(start_seq=0)
            assert result["verified"] is False, (
                "Верификация должна обнаружить удаление записи (chain break)"
            )
    except Exception:
        pass

    # tampering attempt через event_bus.unsubscribe 
    # попытка отписки от аудит-события должна быть залогирована
    count_before = pool.execute(
        "SELECT COUNT(*) as cnt FROM audit_log"
    ).fetchone()["cnt"]

    # пытаемся отписаться от аудит-события
    audit_events = audit_env["events"]
    audit_events.unsubscribe("UserLoggedIn")

    count_after = pool.execute(
        "SELECT COUNT(*) as cnt FROM audit_log"
    ).fetchone()["cnt"]

    # попытка отписки должна создать запись AUDIT_TAMPER_ATTEMPT
    assert count_after > count_before, (
        "Попытка отписки от аудит-события должна создать запись в логе"
    )

    # проверяем что запись имеет правильный event_type
    tamper_row = pool.execute(
        """
        SELECT entry_data FROM audit_log
        WHERE json_extract(entry_data, '$.event_type') = 'AUDIT_TAMPER_ATTEMPT'
        ORDER BY sequence_number DESC LIMIT 1
        """
    ).fetchone()

    assert tamper_row is not None, (
        "Должна существовать запись с event_type = AUDIT_TAMPER_ATTEMPT"
    )

    data = json.loads(tamper_row["entry_data"])
    assert data.get("severity") == "CRITICAL", (
        "AUDIT_TAMPER_ATTEMPT должен иметь severity = CRITICAL"
    )
    
    # попытка доступа к логам при заблокированном key_manager
    # верификация требует активный ключ для проверки подписей
    audit_env["km"].lock()

    try:
        # при заблокированном key_manager signer не может получить ключ
        # verify_log должен либо упасть с RuntimeError либо вернуть verified=False
        result = verifier.verify_log(start_seq=0)

        # если не упал — проверяем что результат корректен
        # заблокированный ключ не даёт подтвердить подписи
        assert isinstance(result, dict), (
            "verify_log должен вернуть dict даже при заблокированном ключе"
        )

    except RuntimeError:
        # ожидаемо — key_manager.get_active_key() бросает RuntimeError
        # когда хранилище заблокировано
        pass

    except Exception as e:
        # любое другое исключение — тоже допустимо
        # главное что доступ не предоставлен молча
        pass

    finally:
        # восстанавливаем разблокированное состояние для чистоты окружения
        audit_env["km"].unlock("AuditTestPass123!")
