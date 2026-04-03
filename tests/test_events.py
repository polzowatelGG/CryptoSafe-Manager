from core.events import EventBus


def test_eventbus_subscribe_publish_unsubscribe(): # тестируем базовую функциональность шины событий: подписка, публикация и отписка
    bus = EventBus()
    called = {}

    def handler(**kwargs): # простой обработчик, который сохраняет аргументы в словарь для проверки
        called.update(kwargs)

    bus.subscribe("ev", handler) # подписываемся на событие "ev"
    bus.publish("ev", x=1)
    assert called.get("x") == 1

    bus.unsubscribe("ev", handler) # отписка от события "ev"
    called.clear()
    bus.publish("ev", x=2)
    assert called == {}
