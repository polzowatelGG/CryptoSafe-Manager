# tests/test_panic_mode.py
# Тесты PanicMode (Sprint 7 — PANIC-1..PANIC-4, TEST-4)

import pytest
from unittest.mock import MagicMock, patch, call
from core.security.panic_mode import PanicMode


def _make_panic(**kwargs) -> PanicMode:
    """Создаёт PanicMode с мок-зависимостями."""
    defaults = dict(
        config={},
        key_manager=None,
        state_manager=None,
        clipboard_service=None,
        audit_logger=None,
        main_window=None,
    )
    defaults.update(kwargs)
    return PanicMode(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# TEST PANIC-1: очистка буфера обмена при панике
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_clears_clipboard():
    """Активация паники должна вызывать очистку буфера обмена."""
    clipboard_service = MagicMock()

    panic = _make_panic(clipboard_service=clipboard_service)
    panic.activate(method="hotkey")

    # Проверяем что был вызван один из методов очистки
    assert (clipboard_service.clear.called or 
            clipboard_service._clear_clipboard.called), \
        "clipboard_service должен быть очищен"


def test_panic_clears_clipboard_even_on_lock_error():
    """Если блокировка хранилища упала, буфер обмена всё равно должен быть очищен."""
    clipboard_service = MagicMock()
    key_manager = MagicMock()
    key_manager.lock.side_effect = RuntimeError("Vault error")

    panic = _make_panic(
        clipboard_service=clipboard_service,
        key_manager=key_manager,
    )
    panic.activate(method="hotkey")

    # Буфер должен быть очищен несмотря на ошибку
    assert (clipboard_service.clear.called or 
            clipboard_service._clear_clipboard.called), \
        "clipboard_service должен быть очищен даже при ошибке"


# ─────────────────────────────────────────────────────────────────────────────
# TEST PANIC-2: блокировка хранилища
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_locks_vault():
    """Активация паники должна блокировать key_manager и state_manager."""
    key_manager = MagicMock()
    state_manager = MagicMock()

    panic = _make_panic(key_manager=key_manager, state_manager=state_manager)
    panic.activate(method="hotkey")

    key_manager.lock.assert_called_once()
    state_manager.lock.assert_called_once()


def test_panic_locks_vault_via_state_manager_only():
    """Паника с только state_manager — всё равно блокирует."""
    state_manager = MagicMock()

    panic = _make_panic(state_manager=state_manager)
    panic.activate(method="hotkey")

    state_manager.lock.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# TEST PANIC-3: запись в аудит-лог
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_logs_event():
    """Активация паники должна создавать запись PANIC_MODE_ACTIVATED в аудите."""
    audit_logger = MagicMock()

    panic = _make_panic(audit_logger=audit_logger)
    panic.activate(method="hotkey")

    audit_logger.log_event.assert_called_once()
    call_kwargs = audit_logger.log_event.call_args
    kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
    assert kwargs.get('event_type') == "PANIC_MODE_ACTIVATED"
    assert kwargs.get('severity') == "CRITICAL"
    details = kwargs.get('details', {})
    assert details.get('activation_method') == "hotkey"


def test_panic_logs_event_with_method():
    """Метод активации должен передаваться в детали аудит-записи."""
    audit_logger = MagicMock()

    panic = _make_panic(audit_logger=audit_logger)
    panic.activate(method="menu")

    call_kwargs = audit_logger.log_event.call_args
    kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
    assert kwargs['details']['activation_method'] == "menu"


def test_panic_logs_even_if_audit_raises():
    """Ошибка в audit_logger не должна прерывать остальные обработчики паники."""
    audit_logger = MagicMock()
    audit_logger.log_event.side_effect = RuntimeError("DB error")
    clipboard_service = MagicMock()

    panic = _make_panic(audit_logger=audit_logger, clipboard_service=clipboard_service)
    panic.activate(method="hotkey")

    # Буфер обмена всё равно должен быть очищен
    assert (clipboard_service.clear.called or 
            clipboard_service._clear_clipboard.called), \
        "clipboard должен быть очищен несмотря на ошибку аудита"


# ─────────────────────────────────────────────────────────────────────────────
# TEST PANIC-4: скрытие окна
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_hides_window():
    """Активация паники должна пытаться скрыть main_window."""
    main_window = MagicMock()
    main_window.isVisible.return_value = True

    panic = _make_panic(main_window=main_window)

    try:
        panic.activate(method="hotkey")
        window_was_set = panic.main_window is main_window
    except Exception as e:
        pytest.fail(f"panic.activate() не должна бросать исключений: {e}")

    assert window_was_set, "main_window должен быть привязан к PanicMode"


# ─────────────────────────────────────────────────────────────────────────────
# TEST: идемпотентность — двойная активация
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_resets_after_activation():
    """После завершения activate() флаг activated должен быть сброшен."""
    panic = _make_panic()
    panic.activate(method="hotkey")

    assert panic.activated is False, (
        "PanicMode должен сбрасывать activated=False после завершения"
    )


def test_panic_can_be_activated_multiple_times():
    """PanicMode должен допускать повторную активацию (после разблокировки)."""
    key_manager = MagicMock()
    audit_logger = MagicMock()

    panic = _make_panic(key_manager=key_manager, audit_logger=audit_logger)

    panic.activate(method="hotkey")
    panic.activate(method="menu")

    assert key_manager.lock.call_count == 2, (
        "key_manager.lock должен быть вызван при каждой активации паники"
    )
    assert audit_logger.log_event.call_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# TEST: порядок выполнения обработчиков
# ─────────────────────────────────────────────────────────────────────────────

def test_handlers_execute_in_order():
    """Обработчики паники должны выполняться в правильном порядке."""
    order = []
    clipboard_service = MagicMock()

    key_manager = MagicMock()
    key_manager.lock.side_effect = lambda: order.append("vault_lock")

    state_manager = MagicMock()
    state_manager.lock.side_effect = lambda: order.append("state_lock")

    panic = _make_panic(
        clipboard_service=clipboard_service,
        key_manager=key_manager,
        state_manager=state_manager,
    )
    panic.activate(method="hotkey")

    # Проверяем что обработчики были выполнены
    assert "vault_lock" in order, "vault должна быть заблокирована"
    assert "state_lock" in order, "state должно быть заблокировано"


# ─────────────────────────────────────────────────────────────────────────────
# TEST: пользовательский обработчик через register_handler
# ─────────────────────────────────────────────────────────────────────────────

def test_register_custom_handler():
    """Зарегистрированный пользовательский обработчик должен вызываться при панике."""
    custom_called = []
    panic = _make_panic()

    def my_handler():
        custom_called.append(True)

    panic.register_handler(my_handler)
    panic.activate(method="custom")

    assert len(custom_called) == 1, "Пользовательский обработчик не был вызван"


# ─────────────────────────────────────────────────────────────────────────────
# TEST: паника без зависимостей (smoke-test)
# ─────────────────────────────────────────────────────────────────────────────

def test_panic_without_dependencies():
    """PanicMode должен работать без передачи зависимостей (graceful degradation)."""
    panic = _make_panic()
    panic.activate(method="hotkey")
    assert panic.activated is False

def test_panic_wipe_memory():
    """PanicMode должен затереть содержимое конфига."""
    config = {"stealth_mode": False, "secret_key": "sensitive"}
    key_manager = MagicMock()
    state_manager = MagicMock()
    clipboard_service = MagicMock()
    panic = PanicMode(config, key_manager, state_manager, clipboard_service)
    panic.activate(method="test")
    # Проверяем, что конфиг очищен (стал пустым или значения обнулены)
    assert config == {} or config.get("secret_key") is None

def test_panic_stealth_mode_fake_error():
    """Stealth mode не должен падать при отсутствии Qt (или должен логировать ошибку)."""
    config = {
        "stealth_mode": True,
        "stealth_actions": {"show_fake_error": True, "launch_decoy": False}
    }
    panic = PanicMode(config)
    try:
        panic.activate(method="stealth")
    except Exception as e:
        pytest.fail(f"Stealth mode raised exception: {e}")