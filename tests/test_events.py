from core import events

def test_subscribe_and_publish():
    called = {"ok": False}

    def handler(**kwargs):
        called["ok"] = True
        called["data"] = kwargs

    events.subscribe("TestEvent", handler)
    events.publish("TestEvent", a=1, b=2)

    assert called["ok"] is True
    assert called.get("data", {}).get("a") == 1

    # очистим подписку
    events.unsubscribe("TestEvent", handler)
