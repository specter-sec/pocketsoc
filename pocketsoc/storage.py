"""A local SQLite events table. No remote database or telemetry."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .models import Event


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.path)
        os.chmod(self.path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
                kind TEXT NOT NULL, source TEXT NOT NULL, source_ip TEXT,
                port INTEGER, username TEXT, password TEXT,
                severity TEXT NOT NULL, rule_id TEXT, mitre TEXT,
                message TEXT NOT NULL, metadata TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
        """)
        self.db.commit()

    def insert(self, event: Event) -> int:
        data = event.to_dict()
        data["metadata"] = json.dumps(data["metadata"], ensure_ascii=False)
        columns = list(data)
        cursor = self.db.execute(
            f"INSERT INTO events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [data[key] for key in columns],
        )
        self.db.commit()
        return int(cursor.lastrowid)

    def for_day(self, day: str | date) -> list[dict]:
        chosen = date.fromisoformat(day) if isinstance(day, str) else day
        start = datetime.combine(chosen, datetime.min.time(), timezone.utc)
        end = start + timedelta(days=1)
        rows = self.db.execute(
            "SELECT * FROM events WHERE timestamp >= ? AND timestamp < ? ORDER BY id",
            (start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item["metadata"])
            result.append(item)
        return result

    def purge(self, retention_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cursor = self.db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self.db.commit()
        return cursor.rowcount

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
