# Security policy

PocketSOC 0.1.x is an educational defensive lab, not a hardened internet-facing appliance. No production uptime or security guarantees are made.

Default listeners bind to loopback. All authentication is rejected. Usernames/passwords are untrusted data, never commands. Password fields are redacted before persistence unless the operator explicitly opts in; Telegram payloads always omit credentials. Raw log copying is separately opt-in. Reports and SQLite may contain personal information and are not encrypted at rest. Keep them in private Termux/Linux storage, restrict access, apply short retention, and do not publish them.

Only Telegram is contacted, and only when explicitly enabled. No GeoIP, analytics, package reputation service, or telemetry endpoint runs in the application. Dependencies are installed during setup; review them independently.

The local config and regex rules are trusted. Regex evaluation is not a hard-timeout sandbox. Resource caps are not protection against a sustained distributed flood. Android can terminate the process; abrupt termination cannot guarantee a final report. Do not run as root or use a shared/attacker-writable data directory.

## Reporting a concern

Never put tokens, passwords, captured logs, private IPs, or a working exploit targeting a real system in a public issue. If GitHub private vulnerability reporting is available, use it. Otherwise open a minimal issue asking IFTIKHAR for a private reporting channel, without sensitive details. Include the affected version and a synthetic reproduction only after a safe channel is established.
