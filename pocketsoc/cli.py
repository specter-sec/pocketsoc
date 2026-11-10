"""PocketSOC command line. No service manager is required."""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import logging
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .app import run
from .config import load_config, require_safe_bind
from .models import Event
from .reports import write_reports
from .storage import Store


@contextmanager
def instance_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+") as handle:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("PocketSOC is already running against this data directory") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def demo_events() -> list[dict]:
    result = []
    for index in range(12):
        ip = ["203.0.113.24", "198.51.100.18", "192.0.2.80"][index % 3]
        username = ["admin", "root", "guest"][index % 3]
        protocol = ["ssh", "telnet", "http"][index % 3]
        stamp = f"2026-01-15T10:{index:02d}:00+00:00"
        common = {"timestamp": stamp, "source_ip": ip, "port": [2222, 2323, 8080][index % 3]}
        result.append(Event(kind="honeypot_connection", source=protocol, **common).to_dict())
        result.append(
            Event(
                kind="credential_attempt",
                source=protocol,
                username=username,
                password="demo-only-password",
                message="Rejected login attempt",
                **common,
            ).to_dict()
        )
        result.append(
            Event(
                kind="detection",
                source=protocol,
                severity="high",
                rule_id="honeypot_credentials",
                mitre="T1110.001",
                message="Credential attempt on a decoy listener",
                **common,
            ).to_dict()
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PocketSOC — a defensive Termux/Linux lab")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("run", "Start listeners and log monitoring"),
        ("check", "Validate configuration without listening"),
        ("report", "Write a daily UTC summary from SQLite"),
    ]:
        item = sub.add_parser(name, help=help_text)
        item.add_argument("--config", default="config.yaml")
        if name in {"run", "check"}:
            item.add_argument(
                "--allow-network",
                action="store_true",
                help="Permit explicitly configured non-loopback binds",
            )
        if name == "report":
            item.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat())
            item.add_argument("--html", action="store_true", help="Also write offline HTML")
    demo = sub.add_parser("demo", help="Write a report containing only synthetic events")
    demo.add_argument("--output-dir", default="reports/demo")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "demo":
            paths = write_reports(demo_events(), "2026-01-15", args.output_dir, demo=True)
        else:
            config = load_config(args.config)
            if args.command in {"run", "check"}:
                require_safe_bind(config, args.allow_network)
            if args.command == "check":
                print(
                    f"Config valid: {len(config.listeners)} listeners, {len(config.rules)} rules. "
                    "No sockets opened and no alerts sent."
                )
                return 0
            if args.command == "run":
                config.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                logfile = config.db_path.parent / "pocketsoc.log"
                handler = RotatingFileHandler(logfile, maxBytes=1_000_000, backupCount=3)
                os.chmod(logfile, 0o600)
                logging.basicConfig(
                    level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    handlers=[logging.StreamHandler(), handler],
                )
                with instance_lock(config.db_path.parent / "pocketsoc.lock"):
                    asyncio.run(run(config, allow_network=args.allow_network))
                return 0
            with Store(config.db_path) as store:
                paths = write_reports(
                    store.for_day(args.date), args.date, config.report_dir, include_html=args.html
                )
        for path in paths:
            print(path)
        return 0
    except (OSError, ValueError) as exc:
        print(f"PocketSOC: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
