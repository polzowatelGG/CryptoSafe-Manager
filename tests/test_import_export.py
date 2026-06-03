# tests/test_import_export.py
# Тесты импорта/экспорта, шаринга и QR-кодов (Спринт 6).

import json
import os
import time
import pytest
from pathlib import Path

from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from core.import_export.exporter import VaultExporter
from core.import_export.importer import VaultImporter, _detect_format, ImportValidationError
from core.import_export.sharing_service import SharingService



# ─────────────────────────────────────────────────────────────────────────────
# Фикстуры
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def vault_env(tmp_path):
    """Полное окружение: БД + KeyManager + EntryManager."""
    db_file = tmp_path / "test_sprint6.db"
    pool    = DatabasePool(str(db_file))
    pool.migrate()

    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {
        "argon2_time":        3,
        "argon2_memory":      65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations":  100000,
    })
    key_manager.initialize("TestPass123!")
    key_manager.unlock("TestPass123!")

    entry_manager = EntryManager(pool, key_manager)

    return {
        "pool":          pool,
        "key_manager":   key_manager,
        "entry_manager": entry_manager,
        "tmp_path":      tmp_path,
    }


@pytest.fixture
def exporter(vault_env):
    return VaultExporter(
        entry_manager=vault_env["entry_manager"],
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )


@pytest.fixture
def importer(vault_env):
    return VaultImporter(
        entry_manager=vault_env["entry_manager"],
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )


@pytest.fixture
def sharing(vault_env):
    return SharingService(
        entry_manager=vault_env["entry_manager"],
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )


def _make_entries(entry_manager, n: int = 10):
    """Создаёт n тестовых записей и возвращает их ID."""
    ids = []
    for i in range(n):
        eid = entry_manager.create_entry({
            "title":    f"Entry {i}",
            "username": f"user{i}@example.com",
            "password": f"Pass{i}!Xy9#",
            "url":      f"https://site{i}.com",
            "notes":    f"Note {i}",
            "category": "Test",
            "tags":     f"tag{i % 3}",
        })
        ids.append(eid)
    return ids


# ─────────────────────────────────────────────────────────────────────────────
# TEST-1: Round-trip — экспорт → импорт → проверка целостности
# ─────────────────────────────────────────────────────────────────────────────

def test_roundtrip_encrypted_json(vault_env, exporter, tmp_path):
    """
    Экспортируем 10 записей в encrypted_json,
    импортируем в новое хранилище,
    проверяем что все данные совпадают.
    """
    em = vault_env["entry_manager"]
    ids = _make_entries(em, 10)

    export_path = str(tmp_path / "export.csafe.json")
    count = exporter.export(
        filepath=export_path,
        password="ExportPass123!",
        format="encrypted_json",
    )
    assert count == 10
    assert Path(export_path).exists()

    # Создаём новое хранилище для импорта
    db2_file = tmp_path / "import_test.db"
    pool2    = DatabasePool(str(db2_file))
    pool2.migrate()

    ks2 = KeyStorage(pool2)
    km2 = KeyManager(ks2, {
        "argon2_time": 3, "argon2_memory": 65536,
        "argon2_parallelism": 4, "pbkdf2_iterations": 100000,
    })
    km2.initialize("TestPass123!")
    km2.unlock("TestPass123!")
    em2 = EntryManager(pool2, km2)

    imp2 = VaultImporter(
        entry_manager=em2,
        key_manager=km2,
        db=pool2,
    )
    result = imp2.import_file(
        filepath=export_path,
        password="ExportPass123!",
        format="encrypted_json",
        mode="merge",
    )

    assert result.imported == 10
    assert result.skipped  == 0
    assert len(result.errors) == 0

    # Проверяем данные
    imported_entries = em2.get_all_entries()
    assert len(imported_entries) == 10

    titles = {e["title"] for e in imported_entries}
    for i in range(10):
        assert f"Entry {i}" in titles

    em2.secure_wipe_list(imported_entries)


def test_roundtrip_csv(vault_env, exporter, tmp_path):
    """Экспорт в CSV → импорт обратно → проверка количества."""
    em  = vault_env["entry_manager"]
    _make_entries(em, 5)

    export_path = str(tmp_path / "export.csv")
    count = exporter.export(
        filepath=export_path,
        password="AnyPass123!",
        format="csv",
    )
    assert count == 5

    # Импортируем в то же хранилище через dry_run
    imp = VaultImporter(
        entry_manager=em,
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )
    result = imp.import_file(
        filepath=export_path,
        format="csv",
        mode="dry_run",
    )
    assert result.total_parsed == 5
    assert len(result.dry_run_entries) == 5


def test_roundtrip_bitwarden(vault_env, exporter, tmp_path):
    """Экспорт в Bitwarden JSON → импорт обратно → проверка данных."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 3)

    export_path = str(tmp_path / "bitwarden.json")
    count = exporter.export(
        filepath=export_path,
        password="AnyPass123!",
        format="bitwarden",
    )
    assert count == 3

    # Создаём второе хранилище
    db2  = tmp_path / "bw_import.db"
    pool2 = DatabasePool(str(db2))
    pool2.migrate()
    ks2 = KeyStorage(pool2)
    km2 = KeyManager(ks2, {
        "argon2_time": 3, "argon2_memory": 65536,
        "argon2_parallelism": 4, "pbkdf2_iterations": 100000,
    })
    km2.initialize("TestPass123!")
    km2.unlock("TestPass123!")
    em2  = EntryManager(pool2, km2)
    imp2 = VaultImporter(entry_manager=em2, key_manager=km2, db=pool2)

    result = imp2.import_file(filepath=export_path, format="bitwarden", mode="merge")
    assert result.imported == 3


# ─────────────────────────────────────────────────────────────────────────────
# TEST-2: Interoperability — LastPass CSV
# ─────────────────────────────────────────────────────────────────────────────

def test_import_lastpass_csv(vault_env, tmp_path):
    """Создаём файл в формате LastPass CSV и импортируем."""
    em  = vault_env["entry_manager"]
    imp = VaultImporter(
        entry_manager=em,
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )

    lastpass_content = (
        "url,username,password,extra,name,grouping,fav\n"
        "https://github.com,dev@example.com,GitPass123!,"
        "some note,GitHub,Work,0\n"
        "https://google.com,user@gmail.com,GooglePass456!,"
        ",Google,Personal,1\n"
        "http://sn,,,secure note content,My Note,,0\n"  # secure note — должна быть пропущена
    )

    lp_file = str(tmp_path / "lastpass.csv")
    with open(lp_file, "w", encoding="utf-8") as f:
        f.write(lastpass_content)

    result = imp.import_file(
        filepath=lp_file,
        format="lastpass_csv",
        mode="merge",
    )

    # Secure notes пропускаются
    assert result.imported == 2
    assert result.skipped  == 0


# ─────────────────────────────────────────────────────────────────────────────
# TEST-3: Sharing security — шаринг + попытка подмены пакета
# ─────────────────────────────────────────────────────────────────────────────

def test_sharing_password_roundtrip(vault_env, sharing):
    """Создаём пакет шаринга паролем → расшифровываем → проверяем данные."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="password",
        recipient="Bob",
        expires_in_days=7,
        password="SharePass123!",
    )

    assert "share_id"   in result
    assert "package"    in result
    assert "expires_at" in result

    # Расшифровываем
    decrypted = sharing.receive_entry(
        package=result["package"],
        password="SharePass123!",
    )

    assert decrypted["title"] == "Entry 0"
    assert decrypted["username"] == "user0@example.com"
    assert "password" in decrypted


def test_sharing_wrong_password(vault_env, sharing):
    """Неверный пароль должен бросить ValueError."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="password",
        password="CorrectPass123!",
    )

    with pytest.raises(ValueError):
        sharing.receive_entry(
            package=result["package"],
            password="WrongPass456!",
        )


def test_sharing_tamper_detection(vault_env, sharing):
    """
    Подмена данных в пакете должна быть обнаружена
    через проверку integrity_hash.
    """
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="password",
        password="SharePass123!",
    )

    package = result["package"]

    # Подменяем integrity_hash — имитируем подмену данных
    package["integrity_hash"] = "a" * 64

    with pytest.raises(ValueError, match="целостност"):
        sharing.receive_entry(
            package=package,
            password="SharePass123!",
        )


def test_sharing_public_key_roundtrip(vault_env, sharing):
    """RSA-OAEP шаринг: создаём ключевую пару → шарим → расшифровываем."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    # Генерируем ключевую пару получателя
    key_pair = sharing.generate_key_pair()
    assert "private_key_pem" in key_pair
    assert "public_key_pem"  in key_pair
    assert "fingerprint"     in key_pair

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="public_key",
        recipient="Alice",
        recipient_public_key_pem=key_pair["public_key_pem"],
    )

    decrypted = sharing.receive_entry(
        package=result["package"],
        private_key_pem=key_pair["private_key_pem"],
    )

    assert decrypted["title"] == "Entry 0"


def test_sharing_save_received(vault_env, sharing):
    """Сохраняем полученную запись в хранилище."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="password",
        password="SharePass123!",
    )
    decrypted = sharing.receive_entry(
        package=result["package"],
        password="SharePass123!",
    )

    count_before = len(em.get_all_entries())
    new_id = sharing.save_received_entry(decrypted)
    count_after  = len(em.get_all_entries())

    assert new_id
    assert count_after == count_before + 1


# ─────────────────────────────────────────────────────────────────────────────
# TEST-4: QR-код
# ─────────────────────────────────────────────────────────────────────────────

def test_qr_generation_requires_library():
    """Проверяем что QRCodeService корректно сообщает о доступности."""
    from core.import_export.key_exchange import QRCodeService
    svc = QRCodeService()
    # Просто проверяем что метод работает без исключений
    available = svc.is_qr_available()
    assert isinstance(available, bool)


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("qrcode"),
    reason="qrcode не установлен"
)
def test_qr_roundtrip(vault_env, sharing):
    """
    Генерируем QR для публичного ключа,
    проверяем структуру результата.
    """
    from core.import_export.key_exchange import QRCodeService

    key_pair = sharing.generate_key_pair()
    svc      = QRCodeService(ttl_seconds=300)

    qr_results = svc.generate_public_key_qr(
        public_key_pem=key_pair["public_key_pem"],
        as_svg=True,
    )

    assert len(qr_results) >= 1
    first = qr_results[0]

    assert "image"      in first
    assert "session_id" in first
    assert "expires_at" in first
    assert first["total"] >= 1
    assert first["chunk"] == 1
    assert first["format"] == "svg"

    # SVG должен быть валидным (начинается с <svg)
    svg = first["image"]
    assert "<svg" in svg.lower()


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("qrcode"),
    reason="qrcode не установлен"
)
def test_qr_ttl_info(sharing):
    """Проверяем что TTL корректно ставится в метаданные."""
    from core.import_export.key_exchange import QRCodeService

    key_pair = sharing.generate_key_pair()
    svc      = QRCodeService(ttl_seconds=60)

    qr_results = svc.generate_public_key_qr(key_pair["public_key_pem"])
    info       = svc.get_qr_info(qr_results)

    assert "expires_at" in info
    assert "session_id" in info


# ─────────────────────────────────────────────────────────────────────────────
# TEST-5: Производительность — 1000 записей
# ─────────────────────────────────────────────────────────────────────────────

def test_performance_export_1000(vault_env, exporter, tmp_path):
    """
    Экспорт 1000 записей должен завершиться менее чем за 5 секунд (PERF-1).
    """
    em = vault_env["entry_manager"]
    _make_entries(em, 1000)

    export_path = str(tmp_path / "perf_export.csafe.json")

    start = time.time()
    count = exporter.export(
        filepath=export_path,
        password="PerfPass123!",
        format="encrypted_json",
    )
    elapsed = time.time() - start

    assert count   == 1000
    assert elapsed < 5.0, (
        f"Экспорт 1000 записей занял {elapsed:.2f}с, ожидалось < 5с"
    )


def test_performance_import_1000(vault_env, exporter, tmp_path):
    """
    Импорт 1000 записей должен завершиться менее чем за 10 секунд (PERF-2).
    """
    em = vault_env["entry_manager"]
    _make_entries(em, 1000)

    export_path = str(tmp_path / "perf_import_src.csafe.json")
    exporter.export(
        filepath=export_path,
        password="PerfPass123!",
        format="encrypted_json",
    )

    # Импортируем в новое хранилище
    db2   = tmp_path / "perf_import.db"
    pool2 = DatabasePool(str(db2))
    pool2.migrate()
    ks2 = KeyStorage(pool2)
    km2 = KeyManager(ks2, {
        "argon2_time": 3, "argon2_memory": 65536,
        "argon2_parallelism": 4, "pbkdf2_iterations": 100000,
    })
    km2.initialize("TestPass123!")
    km2.unlock("TestPass123!")
    em2  = EntryManager(pool2, km2)
    imp2 = VaultImporter(entry_manager=em2, key_manager=km2, db=pool2)

    start = time.time()
    result = imp2.import_file(
        filepath=export_path,
        password="PerfPass123!",
        format="encrypted_json",
        mode="merge",
    )
    elapsed = time.time() - start

    assert result.imported == 1000
    assert elapsed < 10.0, (
        f"Импорт 1000 записей занял {elapsed:.2f}с, ожидалось < 10с"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Дополнительные тесты безопасности
# ─────────────────────────────────────────────────────────────────────────────

def test_export_requires_unlocked_vault(vault_env, tmp_path):
    """Экспорт должен упасть если хранилище заблокировано."""
    km  = vault_env["key_manager"]
    em  = vault_env["entry_manager"]
    _make_entries(em, 1)

    exp = VaultExporter(entry_manager=em, key_manager=km, db=vault_env["pool"])
    km.lock()

    with pytest.raises(PermissionError):
        exp.export(
            filepath=str(tmp_path / "should_fail.json"),
            password="AnyPass123!",
            format="encrypted_json",
        )

    # Восстанавливаем для других тестов
    km.unlock("TestPass123!")


def test_import_file_size_limit(vault_env, tmp_path):
    """Файл > 10 МБ должен быть отклонён."""
    em  = vault_env["entry_manager"]
    imp = VaultImporter(
        entry_manager=em,
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )

    # Создаём файл > 10 МБ
    big_file = str(tmp_path / "big.csv")
    with open(big_file, "wb") as f:
        f.write(b"a" * (11 * 1024 * 1024))

    with pytest.raises(ValueError, match="слишком большой"):
        imp.import_file(filepath=big_file)


def test_import_wrong_password(vault_env, exporter, tmp_path):
    """Неверный пароль при импорте encrypted_json должен бросить ValueError."""
    em = vault_env["entry_manager"]
    _make_entries(em, 3)

    export_path = str(tmp_path / "enc.csafe.json")
    exporter.export(
        filepath=export_path,
        password="CorrectPass123!",
        format="encrypted_json",
    )

    imp = VaultImporter(
        entry_manager=em,
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )

    with pytest.raises(ValueError):
        imp.import_file(
            filepath=export_path,
            password="WrongPass456!",
            format="encrypted_json",
        )


def test_import_dry_run_no_save(vault_env, exporter, tmp_path):
    """Dry-run не должен сохранять записи в хранилище."""
    em = vault_env["entry_manager"]
    _make_entries(em, 5)

    export_path = str(tmp_path / "dryrun.csv")
    exporter.export(
        filepath=export_path,
        password="AnyPass123!",
        format="csv",
    )

    imp = VaultImporter(
        entry_manager=em,
        key_manager=vault_env["key_manager"],
        db=vault_env["pool"],
    )

    count_before = len(em.get_all_entries())
    result = imp.import_file(
        filepath=export_path,
        format="csv",
        mode="dry_run",
    )
    count_after = len(em.get_all_entries())

    # Количество записей не изменилось
    assert count_before == count_after
    # Но превью заполнено
    assert len(result.dry_run_entries) == 5


def test_detect_format_encrypted_json(tmp_path):
    """Авто-определение формата encrypted_json."""
    f = tmp_path / "test.json"
    f.write_text(
        json.dumps({"cryptosafe_export": True, "version": "1.0"}),
        encoding="utf-8"
    )
    assert _detect_format(str(f)) == "encrypted_json"


def test_detect_format_bitwarden(tmp_path):
    """Авто-определение формата bitwarden."""
    f = tmp_path / "bw.json"
    f.write_text(
        json.dumps({"encrypted": False, "items": [{"type": 1, "login": {}}]}),
        encoding="utf-8"
    )
    assert _detect_format(str(f)) == "bitwarden"


def test_detect_format_lastpass(tmp_path):
    """Авто-определение формата lastpass_csv."""
    f = tmp_path / "lp.csv"
    f.write_text(
        "url,username,password,extra,name,grouping,fav\n"
        "https://example.com,user,pass,,Site,Work,0\n",
        encoding="utf-8"
    )
    assert _detect_format(str(f)) == "lastpass_csv"


def test_sharing_contact_save_load(vault_env, sharing):
    """Сохраняем контакт и загружаем его обратно."""
    key_pair = sharing.generate_key_pair()

    contact_id = sharing.save_contact(
        name="Alice",
        public_key_pem=key_pair["public_key_pem"],
        identifier="alice@example.com",
    )
    assert contact_id

    contacts = sharing.get_contacts()
    assert len(contacts) >= 1
    names = [c["name"] for c in contacts]
    assert "Alice" in names


def test_sharing_revoke(vault_env, sharing):
    """Отозванный шаринг не появляется в get_active_shares."""
    em  = vault_env["entry_manager"]
    ids = _make_entries(em, 1)

    result = sharing.share_entry(
        entry_id=ids[0],
        encryption_method="password",
        password="SharePass123!",
    )
    share_id = result["share_id"]

    sharing.revoke_share(share_id)

    active = sharing.get_active_shares()
    active_ids = [s["share_id"] for s in active]
    assert share_id not in active_ids


def test_import_history_recorded(vault_env, exporter, tmp_path):
    """После экспорта запись должна появиться в import_export_history."""
    em = vault_env["entry_manager"]
    _make_entries(em, 2)

    export_path = str(tmp_path / "hist_test.csafe.json")
    exporter.export(
        filepath=export_path,
        password="HistPass123!",
        format="encrypted_json",
    )

    rows = vault_env["pool"].execute(
        "SELECT * FROM import_export_history WHERE operation_type = 'export'"
    ).fetchall()

    assert len(rows) >= 1
    assert rows[-1]["entry_count"] == 2
    assert rows[-1]["format"] == "encrypted_json"
    
def test_qr_service_initialization():
    from core.import_export.key_exchange import QRCodeService
    svc = QRCodeService(ttl_seconds=60)
    assert svc.ttl_seconds == 60
    assert svc.is_qr_available() is not None  # не падает

def test_qr_service_get_qr_info_empty():
    from core.import_export.key_exchange import QRCodeService
    svc = QRCodeService()
    assert svc.get_qr_info([]) == {}
    
def test_export_encrypted_json_with_public_key(vault_env, exporter, tmp_path):
    em = vault_env["entry_manager"]
    em.create_entry({"title": "Test", "password": "pwd"})
    from core.import_export.crypto import generate_rsa_key_pair
    priv, pub = generate_rsa_key_pair()
    output = exporter.export_encrypted_json_for_public_key(pub)
    assert "encrypted_key" in output
    assert "ciphertext" in output

def test_import_corrupted_encrypted_json(vault_env, importer, tmp_path):
    import json
    corrupted = {
        "cryptosafe_export": True,
        "data": {"ciphertext": "invalid_base64!!!"},
        "encryption": {"salt": "AA==", "nonce": "AA=="},
        "integrity": {"checksum": "abc", "payload_checksum": "abc"}
    }
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps(corrupted))
    with pytest.raises((ImportValidationError, ValueError)):
        importer.import_file(str(bad_file), password="any", format="encrypted_json")