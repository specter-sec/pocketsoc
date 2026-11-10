"""End-to-end lifecycle test: loopback only, no real credentials or bot requests."""

import base64
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_full_runtime_collects_detects_and_stops_cleanly(tmp_path):
    with socket.socket() as temporary:
        temporary.bind(("127.0.0.1", 0))
        port = temporary.getsockname()[1]
    config = yaml.safe_load((ROOT / "config.yaml").read_text())
    config["listeners"] = [{"protocol": "http", "host": "127.0.0.1", "port": port}]
    log = tmp_path / "auth.log"
    log.write_text("")
    config["monitor"].update(paths=[str(log)], poll_seconds=0.1)
    config["storage"]["database"] = str(tmp_path / "data" / "events.db")
    config["reports"]["directory"] = str(tmp_path / "reports")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    process = subprocess.Popen(
        [sys.executable, "-m", "pocketsoc", "run", "--config", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                assert process.poll() is None, "PocketSOC exited during startup"
                assert time.monotonic() < deadline, "Listener did not start"
                time.sleep(0.05)
        with client:
            token = base64.b64encode(b"lab-user:synthetic-sensitive-password").decode()
            client.sendall(
                (
                    f"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {token}\r\n\r\n"
                ).encode()
            )
            assert b"401 Unauthorized" in client.recv(4096)
        with log.open("a") as handle:
            handle.write("Failed password for demo from 203.0.113.9 port 44\n" * 5)
        deadline = time.monotonic() + 10
        while True:
            with sqlite3.connect(config["storage"]["database"]) as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM events WHERE rule_id='brute_force'"
                ).fetchone()[0]
            if count:
                break
            assert time.monotonic() < deadline, "Brute-force detection was not persisted"
            time.sleep(0.05)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        assert "synthetic-sensitive-password" not in stderr
        with sqlite3.connect(config["storage"]["database"]) as db:
            password = db.execute(
                "SELECT password FROM events WHERE kind='credential_attempt'"
            ).fetchone()[0]
        assert password == "<redacted>"
        today = datetime.now(timezone.utc).date().isoformat()
        assert (tmp_path / "reports" / f"summary-{today}.md").exists()
        assert (tmp_path / "reports" / f"summary-{today}.html").exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
