import asyncio

import pytest

from pocketsoc.alerts import TelegramAlerter, alert_text
from pocketsoc.models import Event


def setup_alert(monkeypatch, config=None, transport=None, clock=lambda: 0):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "synthetic-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "synthetic-chat")
    return TelegramAlerter({"enabled": True, **(config or {})}, transport=transport, clock=clock)


def test_payload_never_contains_credentials_or_raw_message():
    event = Event(
        kind="detection",
        source="ssh",
        severity="high",
        rule_id="brute_force",
        username="private-user",
        password="private-password",
        message="private-message",
        metadata={"secret": "private-metadata"},
    )
    text = alert_text(event)
    assert all(
        value not in text
        for value in ["private-user", "private-password", "private-message", "private-metadata"]
    )


def test_dedup_rate_cap_and_expiration(monkeypatch):
    now = [0]
    payloads = []
    alert = setup_alert(
        monkeypatch,
        {"max_per_minute": 1, "dedup_seconds": 120},
        transport=lambda token, data: payloads.append(data) or {"ok": True},
        clock=lambda: now[0],
    )
    event = Event(kind="detection", source="ssh", source_ip="192.0.2.1", severity="high")

    async def scenario():
        assert await alert.send(event)
        assert not await alert.send(event)
        now[0] = 61
        assert not await alert.send(event)  # Still deduplicated, though rate window expired.
        now[0] = 121
        assert await alert.send(event)
        assert not await alert.send(Event(kind="detection", source="auth", severity="low"))

    asyncio.run(scenario())
    assert len(payloads) == 2
    assert payloads[0]["protect_content"] is True


def test_backoff_and_failure_does_not_expose_token(monkeypatch, caplog):
    now = [0]
    alert = setup_alert(
        monkeypatch,
        transport=lambda token, data: {"ok": False, "parameters": {"retry_after": 10}},
        clock=lambda: now[0],
    )
    event = Event(kind="detection", source="ssh", severity="high")
    assert not asyncio.run(alert.send(event))
    assert alert.blocked_until == 10
    assert not asyncio.run(alert.send(event))
    assert "synthetic-token" not in caplog.text


def test_enabled_requires_both_environment_values(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with pytest.raises(ValueError, match="TELEGRAM_BOT_TOKEN"):
        TelegramAlerter({"enabled": True})
