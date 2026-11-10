"""Small, bounded, non-interactive SSH, Telnet-like, and HTTP honeypots."""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import math
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs

from .models import Event, clean

Emit = Callable[[Event], Awaitable[None]]
_DEFAULT_LIMITS = {"timeout_seconds": 8.0, "max_connections": 32, "max_bytes": 8192}
LOG = logging.getLogger(__name__)
_last_emit_warning: float | None = None


def _limits(limits: dict[str, Any] | None) -> dict[str, float | int]:
    values: dict[str, Any] = dict(_DEFAULT_LIMITS)
    if limits:
        values.update(limits)
    try:
        timeout = float(values["timeout_seconds"])
        connections = int(values["max_connections"])
        max_bytes = int(values["max_bytes"])
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid honeypot limits") from exc
    if not math.isfinite(timeout) or timeout <= 0 or connections < 1 or max_bytes < 1:
        raise ValueError("limits must be positive finite values")
    return {"timeout_seconds": timeout, "max_connections": connections, "max_bytes": max_bytes}


def _listener_config(listener: dict[str, Any]) -> tuple[str, str, int]:
    try:
        protocol = listener["protocol"]
        host = listener["host"]
        port = listener["port"]
    except (KeyError, TypeError) as exc:
        raise ValueError("listener requires protocol, host, and port") from exc
    if protocol not in {"ssh", "telnet", "http"}:
        raise ValueError("unsupported honeypot protocol")
    if not isinstance(host, str) or not host:
        raise ValueError("listener host must be a non-empty string")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("listener port must be between 0 and 65535")
    return protocol, host, port


async def _emit(emit: Emit, event: Event) -> None:
    """Keep handlers bounded but make degraded persistence visible without data leaks."""
    global _last_emit_warning
    try:
        await emit(event)
    except asyncio.CancelledError:
        raise
    except Exception:
        now = time.monotonic()
        if _last_emit_warning is None or now - _last_emit_warning >= 30:
            LOG.error(
                "Event persistence failed; collection is degraded. Check local storage. "
                "Sensitive error details omitted; this warning is capped to once per 30s."
            )
            _last_emit_warning = now


def _address(writer: asyncio.StreamWriter) -> tuple[str | None, int | None]:
    peer = writer.get_extra_info("peername")
    local = writer.get_extra_info("sockname")
    ip = clean(peer[0], 64) if isinstance(peer, tuple) and peer else None
    port = (
        local[1]
        if isinstance(local, tuple) and len(local) > 1 and isinstance(local[1], int)
        else None
    )
    return ip, port


def _ssh_address(connection: Any) -> tuple[str | None, int | None]:
    peer = connection.get_extra_info("peername")
    local = connection.get_extra_info("sockname")
    ip = clean(peer[0], 64) if isinstance(peer, tuple) and peer else None
    port = (
        local[1]
        if isinstance(local, tuple) and len(local) > 1 and isinstance(local[1], int)
        else None
    )
    return ip, port


class _ManagedServer:
    """Uniform close/wait interface which also owns active client handlers."""

    def __init__(
        self,
        listener: Any,
        *,
        tasks: set[asyncio.Task[Any]] | None = None,
        writers: set[asyncio.StreamWriter] | None = None,
        ssh_connections: set[Any] | None = None,
    ) -> None:
        self._listener = listener
        self._tasks = tasks if tasks is not None else set()
        self._writers = writers if writers is not None else set()
        self._ssh_connections = ssh_connections if ssh_connections is not None else set()
        self._closing = False

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._listener.close()
        for writer in tuple(self._writers):
            writer.close()
        for connection in tuple(self._ssh_connections):
            try:
                connection.close()
            except Exception:
                pass
        current = asyncio.current_task()
        for task in tuple(self._tasks):
            if task is not current and not task.done():
                task.cancel()

    async def wait_closed(self) -> None:
        await self._listener.wait_closed()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        if self._writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in tuple(self._writers)), return_exceptions=True
            )
        if self._ssh_connections:
            await asyncio.gather(
                *(conn.wait_closed() for conn in tuple(self._ssh_connections)),
                return_exceptions=True,
            )


async def _connection_event(emit: Emit, protocol: str, ip: str | None, port: int | None) -> None:
    await _emit(
        emit,
        Event(
            kind="honeypot_connection",
            source=protocol,
            source_ip=ip,
            port=port,
            message="Inbound connection observed.",
            metadata={"protocol": protocol},
        ),
    )


async def _credential_event(
    emit: Emit, protocol: str, ip: str | None, port: int | None, username: str, password: str
) -> None:
    await _emit(
        emit,
        Event(
            kind="credential_attempt",
            source=protocol,
            source_ip=ip,
            port=port,
            username=clean(username),
            password=clean(password),
            severity="medium",
            message="Credential attempt observed.",
            metadata={"protocol": protocol},
        ),
    )


def _track_task(task: asyncio.Task[Any], tasks: set[asyncio.Task[Any]]) -> None:
    tasks.add(task)
    task.add_done_callback(tasks.discard)


async def _start_stream_listener(
    protocol: str, host: str, port: int, emit: Emit, limits: dict[str, float | int]
) -> _ManagedServer:
    max_connections = int(limits["max_connections"])
    max_bytes = int(limits["max_bytes"])
    timeout = float(limits["timeout_seconds"])
    tasks: set[asyncio.Task[Any]] = set()
    writers: set[asyncio.StreamWriter] = set()

    async def finish(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, local_port = _address(writer)
        try:
            await _connection_event(emit, protocol, ip, local_port)
            if protocol == "telnet":
                await asyncio.wait_for(
                    _telnet_dialog(reader, writer, emit, ip, local_port, max_bytes), timeout
                )
            else:
                await asyncio.wait_for(
                    _http_dialog(reader, writer, emit, ip, local_port, max_bytes), timeout
                )
        except (
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            ValueError,
            UnicodeError,
            ConnectionError,
            OSError,
        ):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            writers.discard(writer)

    def accepted(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(writers) >= max_connections:
            writer.close()
            return
        writers.add(writer)
        task = asyncio.create_task(finish(reader, writer))
        _track_task(task, tasks)

    server = await asyncio.start_server(accepted, host=host, port=port, limit=max_bytes + 1)
    return _ManagedServer(server, tasks=tasks, writers=writers)


async def _read_line(reader: asyncio.StreamReader, max_bytes: int) -> bytes:
    line = await reader.readuntil(b"\n")
    if len(line) > max_bytes:
        raise ValueError("input line too large")
    return line.rstrip(b"\r\n")


async def _telnet_dialog(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    emit: Emit,
    ip: str | None,
    port: int | None,
    max_bytes: int,
) -> None:
    writer.write(b"login: ")
    await writer.drain()
    username_raw = await _read_line(reader, max_bytes)
    writer.write(b"Password: ")
    await writer.drain()
    password_raw = await _read_line(reader, max_bytes - len(username_raw))
    if username_raw or password_raw:
        username = username_raw.decode("utf-8", errors="replace")
        password = password_raw.decode("utf-8", errors="replace")
        await _credential_event(emit, "telnet", ip, port, username, password)
    writer.write(b"\r\nLogin incorrect.\r\n")
    await writer.drain()


def _decode_basic(value: str) -> tuple[str, str] | None:
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    try:
        decoded = base64.b64decode(token.strip(), validate=True)
        text = decoded.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None
    username, separator, password = text.partition(":")
    return (username, password) if separator else None


async def _http_dialog(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    emit: Emit,
    ip: str | None,
    port: int | None,
    max_bytes: int,
) -> None:
    headers_raw = await reader.readuntil(b"\r\n\r\n")
    if len(headers_raw) > max_bytes:
        raise ValueError("request headers too large")
    lines = headers_raw[:-4].split(b"\r\n")
    if not lines or len(lines[0]) > 2048:
        raise ValueError("invalid request")
    request_parts = lines[0].split(b" ", 2)
    if len(request_parts) != 3:
        raise ValueError("invalid request")
    try:
        request_method = request_parts[0].decode("ascii", errors="ignore").upper()
    except Exception:
        request_method = ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("ascii", errors="ignore").strip().lower()] = value.decode(
            "latin-1"
        ).strip()

    auth = _decode_basic(headers.get("authorization", ""))
    if auth is not None:
        await _credential_event(emit, "http", ip, port, auth[0], auth[1])

    content_length = 0
    try:
        content_length = int(headers.get("content-length", "0"))
    except ValueError:
        raise ValueError("invalid content length")
    if content_length < 0 or content_length > max_bytes - len(headers_raw):
        raise ValueError("request body too large")
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if request_method == "POST" and content_type == "application/x-www-form-urlencoded":
        body = await reader.readexactly(content_length) if content_length else b""
        fields = parse_qs(
            body.decode("utf-8", errors="replace"),
            keep_blank_values=True,
            encoding="utf-8",
            errors="replace",
            max_num_fields=32,
        )
        if "username" in fields or "password" in fields:
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]
            await _credential_event(emit, "http", ip, port, username, password)

    body_text = (
        "<!doctype html><html><head><title>Login</title></head>"
        "<body><h1>Sign in</h1><p>Login failed. Please try again.</p></body></html>"
    )
    body = body_text.encode("ascii")
    status = b"401 Unauthorized"
    challenge = b'WWW-Authenticate: Basic realm="Sign in"\r\n'
    response = (
        b"HTTP/1.1 "
        + status
        + b"\r\n"
        + challenge
        + b"Content-Type: text/html; charset=utf-8\r\n"
        + b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )
    writer.write(response)
    await writer.drain()


async def _start_ssh_listener(
    host: str, port: int, emit: Emit, limits: dict[str, float | int]
) -> _ManagedServer:
    try:
        import asyncssh
    except ImportError as exc:  # pragma: no cover - project core dependency
        raise RuntimeError("AsyncSSH is required for the SSH honeypot") from exc

    max_connections = int(limits["max_connections"])
    timeout = float(limits["timeout_seconds"])
    connections: set[Any] = set()
    tasks: set[asyncio.Task[Any]] = set()

    class RejectingSSHServer(asyncssh.SSHServer):
        def __init__(self) -> None:
            self.connection: Any | None = None
            self.admitted = False

        def connection_made(self, connection: Any) -> None:
            self.connection = connection
            if len(connections) >= max_connections:
                connection.close()
                return
            self.admitted = True
            connections.add(connection)
            ip, local_port = _ssh_address(connection)
            task = asyncio.create_task(_connection_event(emit, "ssh", ip, local_port))
            _track_task(task, tasks)

        def connection_lost(self, exc: Exception | None) -> None:
            if self.admitted and self.connection is not None:
                connections.discard(self.connection)

        def begin_auth(self, username: str) -> bool:
            return True

        def password_auth_supported(self) -> bool:
            return True

        async def validate_password(self, username: str, password: str) -> bool:
            if self.admitted and self.connection is not None:
                ip, local_port = _ssh_address(self.connection)
                await _credential_event(emit, "ssh", ip, local_port, username, password)
            return False

        def session_requested(self) -> bool:
            return False

        def connection_requested(self, *args: Any, **kwargs: Any) -> bool:
            return False

        def server_requested(self, *args: Any, **kwargs: Any) -> bool:
            return False

        def unix_connection_requested(self, *args: Any, **kwargs: Any) -> bool:
            return False

        def unix_server_requested(self, *args: Any, **kwargs: Any) -> bool:
            return False

    key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        RejectingSSHServer,
        host,
        port,
        server_host_keys=[key],
        password_auth=True,
        public_key_auth=False,
        kbdint_auth=False,
        host_based_auth=False,
        gss_kex=False,
        login_timeout=timeout,
    )
    return _ManagedServer(server, tasks=tasks, ssh_connections=connections)


async def start_listener(
    listener: dict[str, Any], emit: Emit, limits: dict[str, Any] | None = None
) -> _ManagedServer:
    """Start a bounded SSH, Telnet-like, or HTTP credential honeypot.

    The listener binds exactly to the supplied host. No command, shell, file
    transfer, forwarding, or outbound network functionality is provided.
    """
    protocol, host, port = _listener_config(listener)
    effective_limits = _limits(limits)
    if not callable(emit):
        raise TypeError("emit must be an async callable")
    if protocol == "ssh":
        return await _start_ssh_listener(host, port, emit, effective_limits)
    return await _start_stream_listener(protocol, host, port, emit, effective_limits)


async def serve(
    listeners: list[dict[str, Any]],
    emit: Emit,
    stop: asyncio.Event,
    limits: dict[str, Any] | None = None,
) -> None:
    """Run all configured listeners until stopped, always closing them cleanly."""
    started: list[_ManagedServer] = []
    try:
        for listener in listeners:
            started.append(await start_listener(listener, emit, limits))
        await stop.wait()
    finally:
        for server in started:
            server.close()
        if started:
            await asyncio.gather(
                *(server.wait_closed() for server in started), return_exceptions=True
            )
