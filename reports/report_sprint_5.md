# Отчёт по Спринту 5: Журнал аудита с криптографической защитой

**Период:** Основная работа велась 13 мая – 15 мая 2026 года.

**Цель:** Реализована система аудита с hash chain, цифровыми подписями и UI просмотрщиком.

Спринт 5. На пятом этапе реализуется защищенный журнал аудита с:
- криптографической подписью Ed25519 для каждой записи,
- хэш-цепочкой (hash chain) для обнаружения подмены,
- отдельным выводом ключа подписи через HKDF,
- просмотрщиком логов с фильтрацией, поиском и пагинацией,
- экспортом в JSON, CSV и PDF с подтверждением мастер-пароля,
- автоматической верификацией целостности при запуске приложения.


## Выполненные требования

* **ARC-1 - ARC-3:** `audit_logger.py`, `log_signer.py`, `log_verifier.py`, `log_formatters.py`

* **CRY-1 - CRY-4:** Ed25519 подписи + HKDF (audit-signing)

* **LOG-1 - LOG-3:** события auth/CRUD/clipboard/system/security

* **DB-1 - DB-4:** таблица audit_log + индексы + immutability

* **VER-1 - VER-4:** проверка целостности + hash chain

* **GUI-1 - GUI-4:** AuditLogViewer с фильтрацией и поиском

* **EXP-1 - EXP-4:** экспорт JSON/CSV/PDF с подтверждением пароля

## Ключевые технические решения

1. Hash chain + Ed25519 подписи
2. Защита от unsubscribe через EventBus interception
3. Разделение ключей через HKDF

## Тестирование

* test_integrity_tamper_detection
* test_performance_logging_and_verification
* test_security_sql_injection_and_tampering
* test_export_import_integrity

## Основные проблемы и решения

* циклические импорты → delayed imports
* reportlab dependency → добавлен в requirements
* медленная верификация → частичная проверка при старте
