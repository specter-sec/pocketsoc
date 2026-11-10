"""Deterministic, offline daily reports; all untrusted HTML is escaped."""

from __future__ import annotations

import html
import os
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path


def summarize(events: list[dict]) -> dict:
    raw = [e for e in events if e["kind"] != "detection"]
    return {
        "total": len(events),
        "detections": sum(e["kind"] == "detection" for e in events),
        "attempts": sum(e["kind"] == "credential_attempt" for e in events),
        "high": sum(e["kind"] == "detection" and e["severity"] == "high" for e in events),
        "kinds": Counter(e["kind"] for e in events),
        "severities": Counter(e["severity"] for e in events if e["kind"] == "detection"),
        "ips": Counter(e["source_ip"] for e in raw if e.get("source_ip")),
        "users": Counter(e["username"] for e in raw if e.get("username")),
        "passwords": Counter(
            e["password"] for e in raw if e.get("password") not in {None, "", "<redacted>"}
        ),
    }


def _md(value: object) -> str:
    result = str(value).replace("\n", " ").replace("\r", " ")
    for char in "\\|`*_[]<>":
        result = result.replace(char, "\\" + char)
    return result


def _rank(counter: Counter) -> list[tuple]:
    return sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))[:10]


def markdown_report(events: list[dict], day: str, *, demo: bool = False) -> str:
    date.fromisoformat(day)
    summary = summarize(events)
    lines = [f"# PocketSOC daily summary — {day} UTC", "", "Maintainer: IFTIKHAR", ""]
    if demo:
        lines += ["> DEMO: synthetic events and documentation-only IP addresses.", ""]
    lines += [
        f"**{summary['total']} stored events · {summary['detections']} detections · "
        f"{summary['attempts']} credential attempts · {summary['high']} high-severity detections**",
        "",
        "Source IPs are observed peers, not verified attribution. Detection rows are excluded "
        "from source/credential rankings to avoid double-counting.",
        "",
    ]
    for heading, key in [
        ("Event counts", "kinds"),
        ("Detection severity", "severities"),
        ("Top source IPs", "ips"),
        ("Tried usernames", "users"),
        ("Tried passwords (sensitive, opt-in)", "passwords"),
    ]:
        lines += [f"## {heading}", "", "| Value | Count |", "| --- | ---: |"]
        lines += [f"| {_md(value)} | {count} |" for value, count in _rank(summary[key])]
        if not summary[key]:
            lines.append("| None recorded / collection disabled | 0 |")
        lines.append("")
    lines += ["Keep reports private. Never publish reports containing real IPs or credentials.", ""]
    return "\n".join(lines)


def html_report(events: list[dict], day: str, *, demo: bool = False) -> str:
    date.fromisoformat(day)
    data = summarize(events)
    sections = []
    for title, key in [
        ("Observed source IPs", "ips"),
        ("Event counts", "kinds"),
        ("Tried usernames", "users"),
        ("Stored passwords · sensitive", "passwords"),
    ]:
        rows = (
            "".join(
                f"<tr><td>{html.escape(str(value))}</td><td>{count}</td></tr>"
                for value, count in _rank(data[key])
            )
            or '<tr><td colspan="2">None recorded / collection disabled</td></tr>'
        )
        sections.append(
            f"<section><h2>{title}</h2><table><thead><tr><th>Value</th>"
            f"<th>Count</th></tr></thead><tbody>{rows}</tbody></table></section>"
        )
    cards = "".join(
        f'<article class="metric"><span>{label}</span><strong>{value}</strong></article>'
        for label, value in [
            ("Stored events", data["total"]),
            ("Detections", data["detections"]),
            ("Credential attempts", data["attempts"]),
            ("High severity", data["high"]),
        ]
    )
    badge = "SYNTHETIC DEMO · NO REAL ATTACK DATA" if demo else "LOCAL REPORT · KEEP PRIVATE"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PocketSOC — {day}</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#08111c;color:#dce7f3;
font:16px/1.55 system-ui,sans-serif}}main{{max-width:1150px;margin:auto;padding:42px 24px}}
header{{border-bottom:1px solid #26384b;padding-bottom:28px;margin-bottom:28px}}
.eyebrow{{color:#5ddcc5;font-size:12px;letter-spacing:.14em;font-weight:750}}
h1{{font-size:42px;line-height:1.1;letter-spacing:-.04em;margin:12px 0}}h1 span{{color:#5ddcc5}}
p{{color:#a5b8cd;margin:10px 0}}.badge{{display:inline-block;border:1px solid #35505e;
padding:5px 10px;border-radius:5px;font-size:11px;color:#8ce5d5;margin-top:12px}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}}
.metric,section{{background:#101f2f;border:1px solid #23384b;border-radius:12px;padding:20px}}
.metric span{{font-size:12px;color:#a5b8cd}}
.metric strong{{display:block;font-size:34px;color:#fff}}
.metric:last-child strong{{color:#ffb389}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
h2{{font-size:17px;margin:0 0 16px}}table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;padding:9px 0;border-bottom:1px solid #24374a;overflow-wrap:anywhere}}
th{{color:#83a4bf;font-size:11px;text-transform:uppercase;letter-spacing:.1em}}
th:last-child,td:last-child{{text-align:right}}footer{{margin-top:26px;color:#86a0b8;font-size:12px}}
@media(max-width:650px){{.metrics{{grid-template-columns:1fr 1fr}}.grid{{grid-template-columns:1fr}}
h1{{font-size:34px}}main{{padding:24px 16px}}}}
</style></head><body><main><header><div class="eyebrow">POCKETSOC / DAILY FIELD REPORT</div>
<h1>Small footprint.<br><span>Clear security signals.</span></h1>
<p>{day} UTC · Maintainer: IFTIKHAR · Offline HTML summary</p><div class="badge">{badge}</div>
</header><div class="metrics">{cards}</div><div class="grid">{"".join(sections)}</div>
<footer>Observed peers are not verified attribution. Rankings exclude detection duplicates.<br>
Password collection is disabled by default.
Never publish real credentials or personal data.</footer>
</main></body></html>"""


def _write_private(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".pocketsoc-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(
    events: list[dict],
    day: str,
    directory: str | Path,
    *,
    include_html: bool = True,
    demo: bool = False,
) -> list[Path]:
    date.fromisoformat(day)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = [directory / f"summary-{day}.md"]
    _write_private(paths[0], markdown_report(events, day, demo=demo))
    if include_html:
        paths.append(directory / f"summary-{day}.html")
        _write_private(paths[1], html_report(events, day, demo=demo))
    return paths
