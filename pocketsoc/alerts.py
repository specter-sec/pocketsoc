"""Opt-in Telegram alerts. Tokens and credential values are never logged."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections import OrderedDict, deque
from typing import Callable

from .models import SEVERITIES, Event, clean

LOG = logging.getLogger(__name__)


def alert_text(event: Event) -> str:
    # Deliberately exclude message, username, password, and metadata.
    return (
        f"PocketSOC | {event.severity.upper()}\n"
        f"Rule: {clean(event.rule_id or event.kind, 64)}\n"
        f"Source IP: {clean(event.source_ip or 'unknown', 64)}\n"
        f"Port: {event.port if event.port is not None else 'n/a'}\n"
        f"UTC: {clean(event.timestamp, 64)}\n"
        f"ATT&CK: {clean(event.mitre or 'not mapped', 64)}"
    )


def _post(token: str, payload: dict) -> dict:
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read(65536))
    except urllib.error.HTTPError as exc:
        # Telegram's 429 body may include retry_after. Never log the exception URL.
        if exc.code == 429:
            try:
                return json.loads(exc.read(65536))
            except (ValueError, OSError):
                pass
        return {"ok": False}


class TelegramAlerter:
    def __init__(self, config: dict, *, clock: Callable = time.monotonic, transport=None):
        self.enabled = config.get("enabled", False)
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        if self.enabled and (not self.token or not self.chat_id):
            raise ValueError("Enabled Telegram alerts need TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        self.minimum = config.get("min_severity", "medium")
        self.rate = config.get("max_per_minute", 10)
        self.cooldown = config.get("dedup_seconds", 300)
        self.clock = clock
        self.transport = transport or _post
        self.sent: deque[float] = deque()
        self.seen: OrderedDict[tuple, float] = OrderedDict()
        self.lock = asyncio.Lock()
        self.blocked_until = 0.0

    async def send(self, event: Event) -> bool:
        if not self.enabled or SEVERITIES[event.severity] < SEVERITIES[self.minimum]:
            return False
        now = self.clock()
        key = (event.rule_id or event.kind, event.source_ip, event.port)
        async with self.lock:
            while self.sent and self.sent[0] <= now - 60:
                self.sent.popleft()
            if now < self.blocked_until or len(self.sent) >= self.rate:
                return False
            if key in self.seen and now - self.seen[key] < self.cooldown:
                return False
            self.sent.append(now)  # Failed requests count, too: prevent retry storms.
            self.seen.pop(key, None)
            self.seen[key] = now
            while len(self.seen) > 2048:
                self.seen.popitem(last=False)
        payload = {
            "chat_id": self.chat_id,
            "text": alert_text(event),
            "link_preview_options": {"is_disabled": True},
            "protect_content": True,
        }
        try:
            result = await asyncio.to_thread(self.transport, self.token, payload)
            if not result.get("ok"):
                retry = result.get("parameters", {}).get("retry_after", 0)
                if isinstance(retry, (int, float)) and retry > 0:
                    self.blocked_until = self.clock() + min(retry, 3600)
                LOG.warning("Telegram alert not accepted; request details intentionally omitted")
                return False
            return True
        except (OSError, ValueError, urllib.error.URLError):
            LOG.warning("Telegram delivery failed; event remains in local SQLite storage")
            return False
