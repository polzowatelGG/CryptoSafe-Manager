from core.events import EventBus


def test_eventbus_subscribe_publish_unsubscribe():
    bus = EventBus()
    called = {}

    def handler(**kwargs):
        called.update(kwargs)

    bus.subscribe("ev", handler)
    bus.publish("ev", x=1)
    assert called.get("x") == 1

    # тест отписки
    bus.unsubscribe("ev", handler)
    called.clear()
    bus.publish("ev", x=2)
    assert called == {}
