# Contributing to PocketSOC

Maintainer: IFTIKHAR

Keep changes small, defensive, and reviewable. Open an issue describing the user need before introducing new network protocols or outbound services. Never add real credentials, live attacker logs, personal IP addresses, bot tokens, or private chat IDs to a PR.

## Local checks

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
ruff check .
python -m build
```

Use temporary paths, loopback ephemeral ports, documentation IP ranges, and mocked Telegram transports. A new rule needs positive, negative, threshold, and per-source isolation tests. Protocol changes need oversized-input, timeout, rejection, and shutdown coverage. Do not weaken loopback defaults or add command execution.

Rules are trusted regexes, not arbitrary executable plugins. Explain false positives and resource limits. Screenshots must show actual application output and use synthetic, non-sensitive data; label the platform honestly. Termux-specific changes should state the tested Android/Termux versions, or say explicitly when device testing was not performed.

## Pull request checklist

- Describe the behavior and any new trust boundary.
- Add tests and update setup/configuration docs.
- Run pytest and Ruff; keep CI green.
- Confirm `.env`, databases, runtime reports, and private logs are absent.
- Do not post security-sensitive evidence publicly; see SECURITY.md.
