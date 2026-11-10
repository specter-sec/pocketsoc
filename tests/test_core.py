import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pocketsoc.alerts import TelegramAlerter
from pocketsoc.app import Pipeline
from pocketsoc.config import load_config
from pocketsoc.detectors import LogTailer, RuleEngine, extract_ip
from pocketsoc.models import Event
from pocketsoc.reports import html_report, markdown_report, summarize, write_reports
from pocketsoc.storage import Store

ROOT = Path(__file__).resolve().parents[1]


def test_password_redaction_and_control_stripping():
    event = Event(kind="credential_attempt", source="ssh", username="a\x1bb", password="dummy")
    assert event.sanitized().password == "<redacted>"
    assert "\x1b" not in event.sanitized().username
    assert event.sanitized(True).password == "dummy"


def test_sqlite_day_boundary_permissions_and_parameterization(tmp_path):
    with Store(tmp_path / "data" / "events.db") as store:
        store.insert(
            Event(
                kind="credential_attempt",
                source="http",
                username="'; DROP TABLE events;",
                timestamp="2026-01-15T23:59:59+00:00",
            )
        )
        store.insert(Event(kind="probe", source="ssh", timestamp="2026-01-16T00:00:00+00:00"))
        assert len(store.for_day("2026-01-15")) == 1
        assert len(store.for_day("2026-01-16")) == 1
        assert os.stat(store.path).st_mode & 0o777 == 0o600
        assert store.purge(1) == 2


def test_threshold_window_isolated_by_source_and_cooldown():
    clock = [0]
    engine = RuleEngine(
        [
            {
                "id": "brute",
                "pattern": "failed",
                "severity": "high",
                "threshold": 3,
                "window_seconds": 60,
            }
        ],
        clock=lambda: clock[0],
    )
    event = Event(kind="log_line", source="auth", source_ip="192.0.2.1", message="failed login")
    assert not engine.evaluate(event)
    assert not engine.evaluate(event)
    assert len(engine.evaluate(event)) == 1
    assert not engine.evaluate(event)
    other = Event(kind="log_line", source="auth", source_ip="192.0.2.2", message="failed login")
    assert not engine.evaluate(other)
    clock[0] = 61
    assert not engine.evaluate(event)
    assert not engine.evaluate(event)
    assert len(engine.evaluate(event)) == 1
    assert not engine.evaluate(Event(kind="detection", source="auth", message="failed"))


def test_rule_kind_filter_and_single_threshold():
    engine = RuleEngine([{"id": "creds", "kinds": ["credential_attempt"], "severity": "high"}])
    assert not engine.evaluate(Event(kind="honeypot_connection", source="ssh"))
    assert len(engine.evaluate(Event(kind="credential_attempt", source="ssh"))) == 1
    assert len(engine.evaluate(Event(kind="credential_attempt", source="ssh"))) == 1


def test_tailer_start_end_partial_rotation_and_truncation(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("old\n")
    tailer = LogTailer([path])
    assert tailer.poll() == []
    with path.open("a") as handle:
        handle.write("Failed password from 203.0.113.8")
    assert tailer.poll() == []
    with path.open("a") as handle:
        handle.write(" port 22\n")
    events = tailer.poll()
    assert len(events) == 1 and events[0].source_ip == "203.0.113.8"
    path.rename(tmp_path / "auth.log.1")
    path.write_text("new rotated\n")
    assert tailer.poll()[0].message == "new rotated"
    path.write_text("x\n")
    assert tailer.poll()[0].message == "x"


def test_missing_file_then_created_and_oversized_line(tmp_path):
    path = tmp_path / "missing.log"
    tailer = LogTailer([path])
    assert not tailer.poll()
    path.write_text("created\n" + "x" * 9000 + "\nafter\n")
    assert [e.message for e in tailer.poll()] == ["created", "after"]


def test_ip_parser_common_formats():
    assert extract_ip("Failed password from 2001:db8::2 port 22") == "2001:db8::2"
    assert extract_ip("auth failure rhost=192.0.2.9") == "192.0.2.9"
    assert extract_ip("from 999.999.0.1") is None
    assert extract_ip("no source known") is None


def test_report_escapes_and_does_not_double_count(tmp_path):
    events = [
        Event(
            kind="credential_attempt",
            source="http",
            source_ip="192.0.2.1",
            username="<script>alert(1)</script>|[x]",
            password="<redacted>",
        ).to_dict(),
        Event(kind="detection", source="http", source_ip="192.0.2.1", severity="high").to_dict(),
    ]
    data = summarize(events)
    assert data["ips"]["192.0.2.1"] == 1
    assert data["total"] == 2 and not data["passwords"]
    rendered = html_report(events, "2026-01-15", demo=True)
    assert "<script>alert" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "SYNTHETIC DEMO" in rendered
    assert "\\|\\[x\\]" in markdown_report(events, "2026-01-15")
    paths = write_reports(events, "2026-01-15", tmp_path)
    assert len(paths) == 2 and all(p.stat().st_mode & 0o777 == 0o600 for p in paths)
    with pytest.raises(ValueError):
        write_reports(events, "../../escape", tmp_path)


def test_pipeline_redacts_password_and_does_not_copy_raw_log(tmp_path):
    config = load_config(ROOT / "config.yaml")
    config.db_path = tmp_path / "db"
    with Store(config.db_path) as store:
        pipeline = Pipeline(store, config, TelegramAlerter({"enabled": False}))
        asyncio.run(
            pipeline.emit(
                Event(
                    kind="credential_attempt",
                    source="ssh",
                    username="demo",
                    password="not-for-logs",
                )
            )
        )
        asyncio.run(
            pipeline.emit(
                Event(
                    kind="log_line",
                    source="auth",
                    source_ip="192.0.2.3",
                    message="Failed password secret=never-copy-this",
                )
            )
        )
        today = datetime.now(timezone.utc).date().isoformat()
        rows = store.for_day(today)
        assert len(rows) == 4
        assert rows[0]["password"] == "<redacted>"
        assert "never-copy-this" not in str(rows)
        assert pipeline.alerts.empty()
