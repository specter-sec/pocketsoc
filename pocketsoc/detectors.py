"""Trusted regex rules plus a bounded, rotation-aware file monitor."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable

from .models import Event, clean

LOG = logging.getLogger(__name__)
Emit = Callable[[Event], Awaitable[None]]


class RuleEngine:
    def __init__(self, rules: list[dict], clock: Callable[[], float] = time.monotonic):
        self.rules = [(rule, re.compile(rule.get("pattern", ".*"), re.I)) for rule in rules]
        self.clock = clock
        self.buckets: OrderedDict[tuple, tuple[deque, float | None]] = OrderedDict()

    def evaluate(self, event: Event) -> list[Event]:
        if event.kind == "detection":
            return []
        now = self.clock()
        found = []
        for rule, pattern in self.rules:
            if rule.get("kinds") and event.kind not in rule["kinds"]:
                continue
            if not pattern.search(getattr(event, rule.get("field", "message"))[:2048]):
                continue
            key = (rule["id"], event.source_ip or event.source)
            hits, last = self.buckets.pop(key, (deque(), None))
            window = rule.get("window_seconds", 60)
            while hits and hits[0] <= now - window:
                hits.popleft()
            hits.append(now)
            threshold = rule.get("threshold", 1)
            while len(hits) > threshold:
                hits.popleft()
            self.buckets[key] = (hits, last)
            while len(self.buckets) > 4096:
                self.buckets.popitem(last=False)
            if len(hits) < threshold or (
                threshold > 1 and last is not None and now - last < window
            ):
                continue
            self.buckets[key] = (hits, now)
            found.append(
                Event(
                    kind="detection",
                    source=event.source,
                    source_ip=event.source_ip,
                    port=event.port,
                    severity=rule["severity"],
                    rule_id=rule["id"],
                    mitre=rule.get("mitre"),
                    timestamp=event.timestamp,
                    message=clean(rule.get("description", rule["id"]), 512),
                    metadata={
                        "trigger_kind": event.kind,
                        "hits": len(hits),
                        "window_seconds": window,
                    },
                )
            )
        return found


def extract_ip(line: str) -> str | None:
    candidates = re.findall(r"(?:from\s+|rhost=)([0-9a-fA-F:.]+)", line)
    candidates += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate.rstrip(".")))
        except ValueError:
            pass
    return None


@dataclass
class TailState:
    identity: tuple | None = None
    offset: int = 0
    pending: bytes = b""
    first: bool = True
    dropping: bool = False


class LogTailer:
    def __init__(self, paths: list[Path], start_at_end: bool = True):
        self.states = {Path(path): TailState() for path in paths}
        self.start_at_end = start_at_end

    def poll(self) -> list[Event]:
        events = []
        for path, state in self.states.items():
            try:
                stat = path.stat()
                identity = (stat.st_dev, stat.st_ino)
                if identity != state.identity or stat.st_size < state.offset:
                    state.offset = stat.st_size if state.first and self.start_at_end else 0
                    state.pending = b""
                    state.dropping = False
                    state.identity = identity
                state.first = False
                with path.open("rb") as handle:
                    handle.seek(state.offset)
                    data = handle.read(65536)
                    state.offset = handle.tell()
            except (OSError, ValueError):
                # A missing or inaccessible log must not stop listeners.
                state.first = False
                continue
            if state.dropping:
                if b"\n" not in data:
                    continue
                data = data.split(b"\n", 1)[1]
                state.dropping = False
            parts = (state.pending + data).split(b"\n")
            state.pending = parts.pop()
            if len(state.pending) > 8192:
                state.pending = b""
                state.dropping = True
            for part in parts:
                if not part or len(part) > 8192:
                    continue
                line = clean(part.decode("utf-8", errors="replace"), 2048)
                events.append(
                    Event(
                        kind="log_line",
                        source=str(path),
                        source_ip=extract_ip(line),
                        message=line,
                    )
                )
        return events


async def monitor(tailer: LogTailer, emit: Emit, stop: asyncio.Event, interval: float = 1) -> None:
    while not stop.is_set():
        for event in tailer.poll():
            await emit(event)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
