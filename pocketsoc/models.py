"""Small, serializable events shared by the collection pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

SEVERITIES = {"low": 0, "medium": 1, "high": 2}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(value: object, limit: int = 256) -> str:
    """Keep attacker-controlled text bounded and strip terminal control characters."""
    return "".join(c for c in str(value) if c.isprintable())[:limit]


@dataclass(slots=True)
class Event:
    kind: str
    source: str
    timestamp: str = field(default_factory=utc_now)
    source_ip: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    severity: str = "low"
    rule_id: str | None = None
    mitre: str | None = None
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def sanitized(self, capture_passwords: bool = False) -> Event:
        return replace(
            self,
            kind=clean(self.kind, 64),
            source=clean(self.source, 256),
            source_ip=clean(self.source_ip, 64) if self.source_ip else None,
            username=clean(self.username) if self.username is not None else None,
            password=(clean(self.password) if capture_passwords else "<redacted>")
            if self.password is not None
            else None,
            message=clean(self.message, 2048),
            severity=self.severity if self.severity in SEVERITIES else "low",
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
