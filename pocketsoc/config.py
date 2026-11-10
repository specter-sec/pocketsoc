"""Trusted operator configuration. Never executes YAML tags or shell commands."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .models import SEVERITIES


@dataclass(slots=True)
class Config:
    listeners: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    db_path: Path
    report_dir: Path
    log_paths: list[Path]
    capture_passwords: bool
    store_all_logs: bool
    start_at_end: bool
    poll_seconds: float
    retention_days: int
    reports_html: bool
    telegram: dict[str, Any]
    limits: dict[str, int]


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")
    return value


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be true or false")
    return value


def _mapping(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a mapping")
    return value


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    if path.stat().st_size > 1_048_576:
        raise ValueError("Config must be no larger than 1 MiB")
    try:
        raw = _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), "config")
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("Invalid or excessively nested YAML configuration") from exc
    base = path.parent
    load_dotenv(base / ".env", override=False)
    listeners = raw.get("listeners", [])
    if not isinstance(listeners, list) or len(listeners) > 16:
        raise ValueError("listeners must be a list of at most 16 entries")
    seen = set()
    for item in listeners:
        _mapping(item, "listener")
        if item.get("protocol") not in {"ssh", "telnet", "http"}:
            raise ValueError("listener protocol must be ssh, telnet, or http")
        if not isinstance(item.get("host", "127.0.0.1"), str):
            raise ValueError("listener host must be a numeric IP string")
        try:
            ipaddress.ip_address(item.get("host", "127.0.0.1"))
        except ValueError as exc:
            raise ValueError("listener host must be a numeric IP address") from exc
        item.setdefault("host", "127.0.0.1")
        _integer(item.get("port"), "listener port", 1024, 65535)
        key = (item["host"], item["port"])
        if key in seen:
            raise ValueError("duplicate listener host/port")
        seen.add(key)
    rules = raw.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 64:
        raise ValueError("rules must be a list of at most 64 entries")
    ids = set()
    for rule in rules:
        _mapping(rule, "rule")
        rid = rule.get("id", "")
        if not isinstance(rid, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", rid):
            raise ValueError("rule id must contain 1-64 letters, digits, _ or -")
        if rid in ids:
            raise ValueError("rule ids must be unique")
        ids.add(rid)
        if rule.get("severity") not in SEVERITIES:
            raise ValueError("rule severity must be low, medium, or high")
        if rule.get("field", "message") not in {"message", "kind"}:
            raise ValueError("rule field must be message or kind")
        pattern = rule.get("pattern", ".*")
        if not isinstance(pattern, str) or len(pattern) > 512:
            raise ValueError("rule pattern must be a string up to 512 characters")
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError("rule pattern is not a valid regular expression") from exc
        for name in ("description", "mitre"):
            if name in rule and not isinstance(rule[name], str):
                raise ValueError(f"rule {name} must be a string")
        kinds = rule.get("kinds", [])
        if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
            raise ValueError("rule kinds must be a list of strings")
        _integer(rule.get("threshold", 1), "rule threshold", 1, 10000)
        _integer(rule.get("window_seconds", 60), "rule window_seconds", 1, 86400)
    privacy = _mapping(raw.get("privacy", {}), "privacy")
    monitor = _mapping(raw.get("monitor", {}), "monitor")
    storage = _mapping(raw.get("storage", {}), "storage")
    reports = _mapping(raw.get("reports", {}), "reports")
    telegram = _mapping(raw.get("telegram", {}), "telegram")
    limits = _mapping(raw.get("limits", {}), "limits")
    log_paths = monitor.get("paths", [])
    if (
        not isinstance(log_paths, list)
        or len(log_paths) > 64
        or not all(isinstance(p, str) for p in log_paths)
    ):
        raise ValueError("monitor.paths must be a list of at most 64 file paths")
    poll = monitor.get("poll_seconds", 1)
    if type(poll) not in {int, float} or not 0.1 <= poll <= 60:
        raise ValueError("poll_seconds must be between 0.1 and 60")
    _boolean(telegram.get("enabled", False), "telegram.enabled")
    if telegram.get("min_severity", "medium") not in SEVERITIES:
        raise ValueError("telegram.min_severity must be low, medium, or high")
    _integer(telegram.get("max_per_minute", 10), "max_per_minute", 1, 30)
    _integer(telegram.get("dedup_seconds", 300), "dedup_seconds", 1, 86400)

    def relative(value: Any) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("file paths must be non-empty strings")
        return (base / Path(value).expanduser()).resolve()

    return Config(
        listeners=listeners,
        rules=rules,
        db_path=relative(storage.get("database", "data/events.sqlite3")),
        report_dir=relative(reports.get("directory", "reports")),
        log_paths=[relative(p) for p in log_paths],
        capture_passwords=_boolean(privacy.get("capture_passwords", False), "capture_passwords"),
        store_all_logs=_boolean(monitor.get("store_all_lines", False), "store_all_lines"),
        start_at_end=_boolean(monitor.get("start_at_end", True), "start_at_end"),
        poll_seconds=float(poll),
        retention_days=_integer(storage.get("retention_days", 14), "retention_days", 1, 365),
        reports_html=_boolean(reports.get("html", True), "reports.html"),
        telegram=telegram,
        limits={
            "timeout_seconds": _integer(limits.get("timeout_seconds", 8), "timeout_seconds", 1, 60),
            "max_connections": _integer(
                limits.get("max_connections", 32), "max_connections", 1, 256
            ),
            "max_bytes": _integer(limits.get("max_bytes", 8192), "max_bytes", 512, 65536),
        },
    )


def require_safe_bind(config: Config, allow_network: bool) -> None:
    if not allow_network and any(
        not ipaddress.ip_address(item["host"]).is_loopback for item in config.listeners
    ):
        raise ValueError("Non-loopback listeners require the explicit --allow-network option")
