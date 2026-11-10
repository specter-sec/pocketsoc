"""Loopback integration tests for the non-interactive honeypot listeners."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import socket

import asyncssh
import pytest

from pocketsoc.honeypot import serve, start_listener


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _listener(protocol: str, port: int = 0) -> dict[str, object]:
    return {"protocol": protocol, "host": "127.0.0.1", "port": port}


async def _wait_for(events: list, kind: str, count: int = 1) -> list:
    for _ in range(100):
        selected = [event for event in events if event.kind == kind]
        if len(selected) >= count:
            return selected
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {kind} event")


def test_ssh_password_auth_is_rejected_and_captured() -> None:
    async def run() -> None:
        events = []
        server = await start_listener(_listener("ssh"), _async_emit(events))
        try:
            port = server._listener.get_port()
            with pytest.raises(asyncssh.PermissionDenied):
                await asyncssh.connect(
                    "127.0.0.1",
                    port=port,
                    username="attacker",
                    password="dont-record-in-message",
                    known_hosts=None,
                    client_keys=[],
                    preferred_auth=["password"],
                )
            captured = await _wait_for(events, "credential_attempt")
            assert captured[0].source == "ssh"
            assert captured[0].username == "attacker"
            assert captured[0].password == "dont-record-in-message"
            assert captured[0].source_ip == "127.0.0.1"
            assert captured[0].port == port
            assert "dont-record-in-message" not in captured[0].message
            assert "dont-record-in-message" not in repr(captured[0].metadata)
            assert (await _wait_for(events, "honeypot_connection"))[0].source_ip == "127.0.0.1"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def _async_emit(events: list):
    async def emit(event) -> None:
        events.append(event)

    return emit


def test_telnet_prompts_rejects_and_captures_credentials() -> None:
    async def run() -> None:
        events = []
        server = await start_listener(_listener("telnet"), _async_emit(events))
        port = server._listener.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            assert await reader.readexactly(len(b"login: ")) == b"login: "
            writer.write(b"guest\r\n")
            await writer.drain()
            assert await reader.readexactly(len(b"Password: ")) == b"Password: "
            writer.write(b"guessme\r\n")
            await writer.drain()
            assert b"Login incorrect" in await reader.read()
            writer.close()
            await writer.wait_closed()
            captured = await _wait_for(events, "credential_attempt")
            assert captured[0].username == "guest"
            assert captured[0].password == "guessme"
            assert captured[0].port == port
            assert captured[0].message == "Credential attempt observed."
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_http_basic_and_form_credentials_are_captured_without_reflection() -> None:
    async def run() -> None:
        events = []
        server = await start_listener(_listener("http"), _async_emit(events))
        port = server._listener.sockets[0].getsockname()[1]
        try:
            token = base64.b64encode(b"basic-user:basic-secret").decode("ascii")
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                (
                    "GET /private/path?token=private HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    f"Authorization: Basic {token}\r\n\r\n"
                ).encode()
            )
            await writer.drain()
            response = await reader.read()
            assert b"401 Unauthorized" in response
            assert b"basic-secret" not in response
            writer.close()
            await writer.wait_closed()

            body = b"username=form-user&password=form-secret"
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                (
                    "POST /login HTTP/1.1\r\nHost: localhost\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
            response = await reader.read()
            assert b"401 Unauthorized" in response
            assert b"form-secret" not in response
            writer.close()
            await writer.wait_closed()

            captured = await _wait_for(events, "credential_attempt", 2)
            assert [(item.username, item.password) for item in captured] == [
                ("basic-user", "basic-secret"),
                ("form-user", "form-secret"),
            ]
            assert all(item.port == port for item in captured)
            assert all("/private/path" not in repr(item.metadata) for item in captured)
            assert all("private" not in item.message for item in captured)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_telnet_oversized_line_is_closed_safely() -> None:
    async def run() -> None:
        events = []
        server = await start_listener(
            _listener("telnet"), _async_emit(events), limits={"max_bytes": 32, "timeout_seconds": 1}
        )
        port = server._listener.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=64)
            await reader.readexactly(len(b"login: "))
            writer.write(b"x" * 40 + b"\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 1) == b""
            writer.close()
            await writer.wait_closed()
            assert not [event for event in events if event.kind == "credential_attempt"]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_timeout_and_graceful_serve_shutdown_close_active_clients() -> None:
    async def run() -> None:
        events = []
        port = _free_port()
        stop = asyncio.Event()
        task = asyncio.create_task(
            serve(
                [_listener("telnet", port)],
                _async_emit(events),
                stop,
                limits={"timeout_seconds": 2, "max_connections": 2},
            )
        )
        reader = None
        writer = None
        try:
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    break
                except OSError:
                    await asyncio.sleep(0.01)
            assert writer is not None and reader is not None
            assert await reader.readexactly(len(b"login: ")) == b"login: "
            await _wait_for(events, "honeypot_connection")
            stop.set()
            await asyncio.wait_for(task, 2)
            assert await asyncio.wait_for(reader.read(), 1) == b""
        finally:
            if not task.done():
                stop.set()
                await asyncio.wait_for(task, 2)
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    asyncio.run(run())


def test_http_read_timeout_closes_idle_client() -> None:
    async def run() -> None:
        events = []
        server = await start_listener(
            _listener("http"), _async_emit(events), limits={"timeout_seconds": 0.1}
        )
        port = server._listener.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await _wait_for(events, "honeypot_connection")
            assert await asyncio.wait_for(reader.read(), 1) == b""
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_persistence_failure_warns_without_leaking_or_flooding(monkeypatch, caplog):
    from pocketsoc import honeypot
    from pocketsoc.models import Event

    monkeypatch.setattr(honeypot, "_last_emit_warning", None)

    async def failing_emit(event):
        raise OSError("private-password-must-not-leak")

    async def run():
        await honeypot._emit(failing_emit, Event(kind="probe", source="http"))
        await honeypot._emit(failing_emit, Event(kind="probe", source="http"))

    asyncio.run(run())
    assert caplog.text.count("collection is degraded") == 1
    assert "private-password-must-not-leak" not in caplog.text
