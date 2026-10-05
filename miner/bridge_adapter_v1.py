#!/usr/bin/env python3
"""Two-channel HTTP/1.1 adapter for the authorized CTF bridge gateway."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
import math
import os
import random
import re
import secrets
import signal
import socket
import sys
from dataclasses import dataclass
from typing import AsyncIterator, Callable
from urllib.parse import quote, unquote, urlsplit

@dataclass(frozen=True)
class Settings:
    listen_host: str
    listen_port: int
    bridge_url: str
    max_frame: int
    queue_frames: int
    http_timeout: float
    event_timeout: float
    event_poll_enabled: bool
    event_poll_interval: float
    lease_interval: float
    retry_limit: int
    retry_budget: float
    recovery_budget: float
    local_write_timeout: float
    max_response: int
    max_queued_bytes: int
    max_event_connects: int
    reconnect_interval: float
    recovery_stable: float
    startup_jitter_max: float
    ready_file: str
    http_proxy: str
    session_id: str
    generation: str
    capability: str
    filler_slot: str


FILLER_SLOT_PATTERN = re.compile(
    r"^[0-9a-f]{32}/slot_(?:[1-9]|[1-9][0-9]|100)$"
)


def load_settings(environment: dict[str, str] | os._Environ[str] = os.environ) -> Settings:
    defaults = {
        "BRIDGE_LISTEN_HOST": "127.0.0.1", "BRIDGE_LISTEN_PORT": "18080",
        "BRIDGE_URL": "", "BRIDGE_MAX_FRAME": str(256 * 1024),
        "BRIDGE_QUEUE_FRAMES": "64", "BRIDGE_HTTP_TIMEOUT": "30",
        "BRIDGE_EVENT_TIMEOUT": "65", "BRIDGE_LEASE_INTERVAL": "30",
        "BRIDGE_EVENT_POLL_ENABLED": "0", "BRIDGE_EVENT_POLL_INTERVAL": "2",
        "BRIDGE_RETRY_LIMIT": "8", "BRIDGE_RETRY_BUDGET": "30",
        "BRIDGE_RECOVERY_BUDGET": "120", "BRIDGE_LOCAL_WRITE_TIMEOUT": "10",
        "BRIDGE_MAX_RESPONSE": str(1024 * 1024),
        "BRIDGE_MAX_QUEUED_BYTES": str(16 * 1024 * 1024),
        "BRIDGE_MAX_EVENT_CONNECTS": "16", "BRIDGE_RECONNECT_INTERVAL": "0.05",
        "BRIDGE_RECOVERY_STABLE": "5", "BRIDGE_STARTUP_JITTER_MAX": "0",
        "BRIDGE_READY_FILE": "", "BRIDGE_HTTP_PROXY": "",
        "BRIDGE_SESSION_ID": "", "BRIDGE_GENERATION": "",
        "BRIDGE_CAPABILITY": "", "BRIDGE_FILLER_SLOT": "",
    }

    def raw(name: str) -> str:
        return environment.get(name, defaults[name])

    def integer(name: str) -> int:
        try:
            value = int(raw(name))
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if value <= 0:
            raise ValueError(f"{name} must be positive")
        return value

    def number(name: str, *, allow_zero: bool = False) -> float:
        try:
            value = float(raw(name))
        except ValueError as exc:
            raise ValueError(f"{name} must be a number") from exc
        if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
            qualification = "finite and nonnegative" if allow_zero else "finite and positive"
            raise ValueError(f"{name} must be {qualification}")
        return value

    def boolean(name: str) -> bool:
        value = raw(name).strip().lower()
        if value not in {"0", "1"}:
            raise ValueError(f"{name} must be 0 or 1")
        return value == "1"

    # An explicitly supplied app-specific value, including an empty value,
    # is authoritative.  This prevents an ambient HTTP_PROXY from silently
    # changing the fixed production route.
    if "BRIDGE_HTTP_PROXY" in environment:
        proxy_value = environment["BRIDGE_HTTP_PROXY"]
    else:
        proxy_value = environment.get("HTTP_PROXY") or environment.get("http_proxy") or ""
    settings = Settings(
        raw("BRIDGE_LISTEN_HOST"), integer("BRIDGE_LISTEN_PORT"), raw("BRIDGE_URL"),
        integer("BRIDGE_MAX_FRAME"), integer("BRIDGE_QUEUE_FRAMES"),
        number("BRIDGE_HTTP_TIMEOUT"), number("BRIDGE_EVENT_TIMEOUT"),
        boolean("BRIDGE_EVENT_POLL_ENABLED"), number("BRIDGE_EVENT_POLL_INTERVAL"),
        number("BRIDGE_LEASE_INTERVAL"), integer("BRIDGE_RETRY_LIMIT"),
        number("BRIDGE_RETRY_BUDGET"), number("BRIDGE_RECOVERY_BUDGET"),
        number("BRIDGE_LOCAL_WRITE_TIMEOUT"), integer("BRIDGE_MAX_RESPONSE"),
        integer("BRIDGE_MAX_QUEUED_BYTES"), integer("BRIDGE_MAX_EVENT_CONNECTS"),
        number("BRIDGE_RECONNECT_INTERVAL"),
        number("BRIDGE_RECOVERY_STABLE"), number("BRIDGE_STARTUP_JITTER_MAX", allow_zero=True),
        raw("BRIDGE_READY_FILE"), proxy_value, raw("BRIDGE_SESSION_ID"),
        raw("BRIDGE_GENERATION"), raw("BRIDGE_CAPABILITY"),
        raw("BRIDGE_FILLER_SLOT"),
    )
    if not settings.listen_host:
        raise ValueError("BRIDGE_LISTEN_HOST must not be empty")
    if not (1 <= settings.listen_port <= 65535):
        raise ValueError("BRIDGE_LISTEN_PORT must be between 1 and 65535")
    validate_bridge_url(settings.bridge_url)
    validate_http_proxy(settings.http_proxy)
    if settings.max_queued_bytes < settings.max_frame:
        raise ValueError("BRIDGE_MAX_QUEUED_BYTES cannot be smaller than BRIDGE_MAX_FRAME")
    if settings.recovery_stable > settings.recovery_budget:
        raise ValueError("BRIDGE_RECOVERY_STABLE cannot exceed BRIDGE_RECOVERY_BUDGET")
    if settings.event_poll_enabled and settings.event_poll_interval <= 0:
        raise ValueError("BRIDGE_EVENT_POLL_INTERVAL must be positive when event polling is enabled")
    identity = (settings.session_id, settings.generation, settings.capability)
    if any(identity) != all(identity):
        raise ValueError("Bridge control identity must be supplied as one complete set")
    if all(identity) and (
        re.fullmatch(r"[0-9a-f]{32}", settings.session_id) is None
        or re.fullmatch(r"[0-9a-f]{32}", settings.generation) is None
        or re.fullmatch(r"[0-9a-f]{64}", settings.capability) is None
    ):
        raise ValueError("Bridge control identity is invalid")
    if settings.filler_slot and FILLER_SLOT_PATTERN.fullmatch(settings.filler_slot) is None:
        raise ValueError("BRIDGE_FILLER_SLOT is invalid")
    return settings


def validate_bridge_url(value: str):
    """Accept one explicit HTTP IPv4 or conventional DNS endpoint."""
    target = urlsplit(value)
    try:
        port = target.port
    except ValueError as exc:
        raise ValueError("BRIDGE_URL has an invalid port") from exc
    hostname = (target.hostname or "").lower().rstrip(".")
    literal_ip = True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = False
        labels = hostname.split(".")
        valid_hostname = (
            1 <= len(hostname) <= 253
            and len(labels) >= 2
            and all(
                label
                and len(label) <= 63
                and not label.startswith("-")
                and not label.endswith("-")
                and all(
                    character.isascii()
                    and (character.isalnum() or character == "-")
                    for character in label
                )
                for label in labels
            )
        )
        if not valid_hostname:
            raise ValueError(
                "BRIDGE_URL must contain an IPv4 address or DNS hostname"
            )
    if (
        target.scheme != "http"
        or target.username is not None
        or target.password is not None
        or port is None
        or not (1 <= port <= 65535)
        or target.path
        or target.query
        or target.fragment
        or (
            literal_ip
            and (
                address.is_unspecified
                or address.is_multicast
                or address.version != 4
            )
        )
    ):
        raise ValueError(
            "BRIDGE_URL must be a plain HTTP IPv4 or DNS endpoint"
        )
    return target


def validate_http_proxy(value: str):
    if not value:
        return urlsplit("")
    proxy = urlsplit(value)
    try:
        port = proxy.port
    except ValueError as exc:
        raise ValueError("HTTP proxy has an invalid port") from exc
    if (
        proxy.scheme != "http"
        or not proxy.hostname
        or port is not None and not (1 <= port <= 65535)
        or port is None and proxy.netloc.endswith(":")
        or proxy.path
        or proxy.query
        or proxy.fragment
    ):
        raise ValueError("HTTP proxy must be a plain HTTP endpoint")
    return proxy


SETTINGS = load_settings()
LISTEN_HOST = SETTINGS.listen_host
LISTEN_PORT = SETTINGS.listen_port
BRIDGE_URL = SETTINGS.bridge_url
MAX_FRAME = SETTINGS.max_frame
QUEUE_FRAMES = SETTINGS.queue_frames
HTTP_TIMEOUT = SETTINGS.http_timeout
EVENT_TIMEOUT = SETTINGS.event_timeout
LEASE_INTERVAL = SETTINGS.lease_interval
RETRY_LIMIT = SETTINGS.retry_limit
RETRY_BUDGET = SETTINGS.retry_budget
RECOVERY_BUDGET = SETTINGS.recovery_budget
LOCAL_WRITE_TIMEOUT = SETTINGS.local_write_timeout
MAX_RESPONSE = SETTINGS.max_response
MAX_QUEUED_BYTES = SETTINGS.max_queued_bytes
MAX_EVENT_CONNECTS = SETTINGS.max_event_connects
RECONNECT_INTERVAL = SETTINGS.reconnect_interval
RECOVERY_STABLE = SETTINGS.recovery_stable
STARTUP_JITTER_MAX = SETTINGS.startup_jitter_max

# A `create_paused` refusal is the Gateway saying its host is already over the
# CPU pressure threshold.  Retrying inside the normal 30s budget re-arms the
# storm that keeps it there: measured ~0.1 CREATE/second per adapter at a 0%
# success rate, which alone held a 2-core host at 98% and prevented the
# Gateway from ever clearing its pause.
#
# The steady-state retry rate is (live adapters / backoff).  With ~850
# adapters a 60s backoff still produced ~14 attempts/second, which is itself
# enough CPU to hold the host at the threshold.  Five minutes drops that to
# ~3/second while remaining far shorter than a container's lifetime, so a
# paused adapter still retries several times before it dies.  The deadline is
# extended by the same amount so the sleep is not cut short by the budget.
PAUSE_RETRY_SECONDS = 300.0
PAUSE_RETRY_JITTER_SECONDS = 5.0
READY_FILE = SETTINGS.ready_file
CREATE_BODY = b'{"protocol":"stratum-json-lines","version":1}'
LEASE_BODY = b'{}'


def max_event_line_bytes(max_frame: int, generation: str) -> int:
    # A Gateway event re-encodes the decoded frame with ensure_ascii=True. Each
    # UTF-8 input byte can produce at most three ASCII escape bytes.
    envelope = json.dumps(
        {"generation": generation, "server_seq": 2**63 - 1, "type": "stratum", "frame": None},
        separators=(",", ":"),
    ).encode("ascii")
    return 3 * max_frame + len(envelope) - len(b"null")


def telemetry(event: str, **fields: object) -> None:
    print(json.dumps({"component": "bridge_adapter", "event": event, **fields}, separators=(",", ":")), file=sys.stderr, flush=True)


class SessionReset(Exception):
    pass


class IntendedLocalEOF(Exception):
    pass


class HTTPProtocolError(SessionReset):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    version: str = "HTTP/1.1"


@dataclass
class HTTPConnection:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None


class HTTPClient:
    def __init__(
        self, base_url: str, settings: Settings = SETTINGS, *,
        _test_allow_unvalidated_transport: bool = False,
    ) -> None:
        self.settings = settings
        if _test_allow_unvalidated_transport:
            target = urlsplit(base_url)
            if target.scheme != "http" or not target.hostname:
                raise ValueError("BRIDGE_URL must be an http URL")
        else:
            if base_url != settings.bridge_url:
                raise ValueError("BRIDGE_URL differs from the validated settings")
            target = validate_bridge_url(base_url)
        self.target = target
        self.proxy = validate_http_proxy(settings.http_proxy)

    def _destination(self) -> tuple[str, int]:
        if self.proxy.hostname:
            return self.proxy.hostname, self.proxy.port or 80
        return self.target.hostname or "", self.target.port or 80

    def _request_target(self, path: str) -> str:
        if self.proxy.hostname:
            port = f":{self.target.port}" if self.target.port and self.target.port != 80 else ""
            return f"http://{self.target.hostname}{port}{path}"
        return path

    def _headers(self, extra: dict[str, str], body: bytes | None, close: bool) -> dict[str, str]:
        port = f":{self.target.port}" if self.target.port and self.target.port != 80 else ""
        result = {"Host": f"{self.target.hostname}{port}", "Connection": "close" if close else "keep-alive"}
        result.update(extra)
        if body is not None:
            result["Content-Length"] = str(len(body))
        if self.proxy.username is not None:
            raw = f"{unquote(self.proxy.username)}:{unquote(self.proxy.password or '')}".encode()
            result["Proxy-Authorization"] = "Basic " + base64.b64encode(raw).decode()
        return result

    @staticmethod
    async def _until(awaitable, end: float | None, fallback: float):
        timeout=fallback if end is None else min(fallback,end-asyncio.get_running_loop().time())
        if timeout<=0:raise asyncio.TimeoutError
        return await asyncio.wait_for(awaitable,timeout)

    async def open_request(self, method: str, path: str, headers: dict[str, str], body: bytes | None = None, *, close: bool = True, end: float | None = None) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, Response]:
        host, port = self._destination()
        reader, writer = await self._until(asyncio.open_connection(host, port),end,self.settings.http_timeout)
        all_headers = self._headers(headers, body, close)
        request = f"{method} {self._request_target(path)} HTTP/1.1\r\n".encode("ascii")
        request += b"".join(f"{key}: {value}\r\n".encode("ascii") for key, value in all_headers.items()) + b"\r\n"
        writer.write(request)
        if body is not None:
            writer.write(body)
        await self._until(writer.drain(),end,self.settings.http_timeout)
        try:
            response = await self._read_response_head(reader, end)
        except BaseException:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise
        return reader, writer, response

    async def close_connection(self, connection: HTTPConnection) -> None:
        writer = connection.writer
        connection.reader = None
        connection.writer = None
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1.0)

    @staticmethod
    def _persistent(version: str, headers: dict[str, str]) -> bool:
        tokens = {token.strip().lower() for token in headers.get("connection", "").split(",")}
        if "close" in tokens:
            return False
        if version == "HTTP/1.1":
            return True
        if version == "HTTP/1.0":
            return "keep-alive" in tokens
        return False

    async def request(self, method: str, path: str, headers: dict[str, str], body: bytes | None = None, *, end: float | None = None, connection: HTTPConnection | None = None) -> Response:
        if connection is None:
            reader, writer, head = await self.open_request(method, path, headers, body,end=end)
            try:
                payload = await self._read_body(reader, head.headers, end, method=method, status=head.status)
                return Response(head.status, head.headers, payload, head.version)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await self._until(writer.wait_closed(),end,1.0)
        if connection.writer is None or connection.writer.is_closing() or connection.reader is None or connection.reader.at_eof():
            await self.close_connection(connection)
            host, port = self._destination()
            connection.reader, connection.writer = await self._until(asyncio.open_connection(host, port),end,self.settings.http_timeout)
        reader, writer = connection.reader, connection.writer
        try:
            all_headers = self._headers(headers, body, False)
            request = f"{method} {self._request_target(path)} HTTP/1.1\r\n".encode("ascii")
            request += b"".join(f"{key}: {value}\r\n".encode("ascii") for key, value in all_headers.items()) + b"\r\n"
            writer.write(request)
            if body is not None:
                writer.write(body)
            await self._until(writer.drain(),end,self.settings.http_timeout)
            head = await self._read_response_head(reader, end)
            payload = await self._read_body(reader, head.headers, end, method=method, status=head.status)
            result = Response(head.status, head.headers, payload, head.version)
            bodyless = method == "HEAD" or 100 <= head.status < 200 or head.status in {204, 304}
            if not self._persistent(head.version, head.headers) or not bodyless and "content-length" not in head.headers and not head.headers.get("transfer-encoding"):
                await self.close_connection(connection)
            return result
        except BaseException:
            await self.close_connection(connection)
            raise

    async def _read_response_head(self, reader: asyncio.StreamReader, end: float | None = None) -> Response:
        head = await self._read_head(reader, end)
        while 100 <= head.status < 200:
            if head.status == 101:
                raise HTTPProtocolError("HTTP protocol upgrade is unsupported")
            if head.headers.get("transfer-encoding") or head.headers.get("content-length") not in {None, "0"}:
                raise HTTPProtocolError("informational HTTP response has body framing")
            head = await self._read_head(reader, end)
        return head

    async def _read_head(self, reader: asyncio.StreamReader, end: float | None = None) -> Response:
        status_line = await self._until(reader.readline(),end,self.settings.http_timeout)
        if len(status_line) > 8192 or not status_line.endswith(b"\n"):
            raise HTTPProtocolError("invalid HTTP status line")
        parts = status_line.decode("latin1").strip().split(None, 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
            raise HTTPProtocolError("invalid HTTP response")
        headers: dict[str, str] = {}
        total = len(status_line)
        while True:
            line = await self._until(reader.readline(),end,self.settings.http_timeout)
            total += len(line)
            if total > 65536 or not line.endswith(b"\n"):
                raise HTTPProtocolError("invalid HTTP headers")
            if line in (b"\r\n", b"\n"):
                break
            if b":" not in line:
                raise HTTPProtocolError("invalid HTTP header")
            key, value = line.decode("latin1").split(":", 1)
            lower = key.strip().lower()
            value = value.strip()
            if lower in headers:
                if lower in {"content-length", "transfer-encoding"}:
                    raise HTTPProtocolError("duplicate HTTP response framing header")
                headers[lower] += ", " + value
            else:
                headers[lower] = value
        if parts[0] not in {"HTTP/1.0", "HTTP/1.1"}:
            raise HTTPProtocolError("unsupported HTTP response version")
        return Response(int(parts[1]), headers, b"", parts[0])

    async def _read_body(
        self, reader: asyncio.StreamReader, headers: dict[str, str],
        end: float | None = None, *, method: str = "GET", status: int = 200,
    ) -> bytes:
        transfer = headers.get("transfer-encoding", "").lower()
        length = headers.get("content-length")
        bodyless = method == "HEAD" or 100 <= status < 200 or status in {204, 304}
        if transfer and length is not None:
            raise HTTPProtocolError("HTTP response has TE and CL")
        if bodyless:
            if transfer:
                raise HTTPProtocolError("bodyless HTTP response has transfer encoding")
            if status == 204 and length not in {None, "0"}:
                raise HTTPProtocolError("HTTP 204 response has nonzero content length")
            return b""
        if transfer:
            if transfer != "chunked":
                raise HTTPProtocolError("unsupported transfer encoding")
            chunks = bytearray()
            async for chunk in self.iter_chunked(reader,end=end):
                chunks.extend(chunk)
                if len(chunks) > self.settings.max_response:
                    raise HTTPProtocolError("HTTP response too large")
            return bytes(chunks)
        if length is None:
            chunks = bytearray()
            while True:
                chunk = await self._until(reader.read(min(65536, self.settings.max_response + 1 - len(chunks))),end,self.settings.http_timeout)
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > self.settings.max_response:
                    raise HTTPProtocolError("HTTP response too large")
            data = bytes(chunks)
        else:
            if not length.isdigit() or int(length) > self.settings.max_response:
                raise HTTPProtocolError("invalid content length")
            data = await self._until(reader.readexactly(int(length)),end,self.settings.http_timeout)
        if len(data) > self.settings.max_response:
            raise HTTPProtocolError("HTTP response too large")
        return data

    async def iter_event_body(self, reader: asyncio.StreamReader, headers: dict[str, str], end: float | None = None) -> AsyncIterator[bytes]:
        transfer = headers.get("transfer-encoding", "").lower()
        length = headers.get("content-length")
        if transfer and length is not None:
            raise HTTPProtocolError("HTTP response has TE and CL")
        if length is not None:
            raise HTTPProtocolError("events response has content length")
        if transfer:
            if transfer != "chunked":
                raise HTTPProtocolError("unsupported transfer encoding")
            async for chunk in self.iter_chunked(reader, end=end):
                yield chunk
            return
        while True:
            chunk = await self._until(reader.read(65536), end, self.settings.event_timeout)
            if not chunk:
                return
            yield chunk

    async def iter_chunked(self, reader: asyncio.StreamReader, end: float | None = None) -> AsyncIterator[bytes]:
        while True:
            line = await self._until(reader.readline(),end,self.settings.event_timeout)
            if not line:
                raise OSError("chunked response EOF")
            if len(line) > 1024 or not line.endswith(b"\n"):
                raise HTTPProtocolError("invalid chunk header")
            token = line.strip().split(b";", 1)[0]
            try:
                size = int(token, 16)
            except ValueError as exc:
                raise HTTPProtocolError("invalid chunk size") from exc
            if size > self.settings.max_response:
                raise HTTPProtocolError("chunk too large")
            if size == 0:
                while True:
                    trailer = await self._until(reader.readline(),end,self.settings.http_timeout)
                    if len(trailer) > 8192 or not trailer.endswith(b"\n"):
                        raise HTTPProtocolError("invalid trailer")
                    if trailer in (b"\r\n", b"\n"):
                        return
            data = await self._until(reader.readexactly(size),end,self.settings.event_timeout)
            if await self._until(reader.readexactly(2),end,self.settings.http_timeout) != b"\r\n":
                raise HTTPProtocolError("invalid chunk delimiter")
            yield data


class ResourceBudget:
    def __init__(self, byte_limit: int) -> None:
        if byte_limit < 1:
            raise ValueError("BRIDGE_MAX_QUEUED_BYTES must be positive")
        self.byte_limit = byte_limit
        self.queued_bytes = 0

    def reserve(self, size: int) -> bool:
        if size > self.byte_limit - self.queued_bytes:
            return False
        self.queued_bytes += size
        return True

    def release(self, size: int) -> None:
        self.queued_bytes -= size
        if self.queued_bytes < 0:
            raise RuntimeError("adapter queued-byte accounting underflow")


class ReconnectGate:
    def __init__(
        self, concurrency: int, interval: float, *,
        uniform: Callable[[float, float], float] = random.uniform,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], object] = asyncio.sleep,
    ) -> None:
        if concurrency < 1 or interval <= 0:
            raise ValueError("invalid bridge reconnect limits")
        self.semaphore = asyncio.Semaphore(concurrency)
        self.interval = interval
        self.uniform = uniform
        self.clock = clock
        self.sleep = sleep
        self.lock = asyncio.Lock()
        self.next_attempt = 0.0

    def _time(self) -> float:
        return self.clock() if self.clock is not None else asyncio.get_running_loop().time()

    @contextlib.asynccontextmanager
    async def admission(self):
        async with self.semaphore:
            async with self.lock:
                now = self._time()
                slot = max(now, self.next_attempt)
                self.next_attempt = slot + self.uniform(0.5 * self.interval, 1.5 * self.interval)
            delay = max(0.0, slot - now)
            if delay:
                await self.sleep(delay)
            yield


class AdapterSession:
    def __init__(
        self, local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter,
        client: HTTPClient, budget: ResourceBudget | None = None,
        reconnect_gate: ReconnectGate | None = None, *, settings: Settings = SETTINGS,
        uniform: Callable[[float, float], float] = random.uniform,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], object] = asyncio.sleep,
    ) -> None:
        self.local_reader = local_reader
        self.local_writer = local_writer
        self.client = client
        self.settings = settings
        self.uniform = uniform
        self.clock = clock or asyncio.get_running_loop().time
        self.sleep = sleep
        self.session_id = settings.session_id or secrets.token_hex(16)
        self.generation = settings.generation or secrets.token_urlsafe(16)
        self.capability = settings.capability or secrets.token_hex(32)
        self.cursor = 0
        self.queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue(settings.queue_frames)
        self.post_lock = asyncio.Lock()
        self.http_connection = HTTPConnection()
        self.events_ready = asyncio.Event()
        self.budget = budget or ResourceBudget(settings.max_queued_bytes)
        self.reconnect_gate = reconnect_gate or ReconnectGate(settings.max_event_connects, settings.reconnect_interval, uniform=uniform, clock=self.clock, sleep=sleep)
        self.closed = False
        self.drain_end: float | None = None
        self.create_may_exist = False
        self.cleanup_started = False

    @property
    def root(self) -> str:
        return f"/bridge/v1/sessions/{quote(self.session_id)}"

    def headers(self, request_id: str | None = None) -> dict[str, str]:
        result = {"X-Bridge-Source": "envoy", "X-Bridge-Capability": self.capability, "X-Bridge-Generation": self.generation}
        if request_id:
            result["X-Request-ID"] = request_id
        return result

    async def run(self) -> None:
        tasks: list[asyncio.Task] = []
        ready_task: asyncio.Task | None = None
        try:
            initial = await self._read_local_frame(initial=True)
            assert initial is not None
            initial_body, initial_value = initial
            if initial_value.get("method") != "login":
                raise SessionReset("first local frame must be login")
            bootstrapped = await self._bootstrap_or_create(initial_body)
            events_task = asyncio.create_task(self._events(), name="adapter-events")
            tasks.append(events_task)
            ready_task = asyncio.create_task(self.events_ready.wait(), name="adapter-events-ready")
            done, _ = await asyncio.wait(
                (events_task, ready_task),
                timeout=self.settings.http_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if ready_task in done and ready_task.result():
                pass
            elif events_task in done:
                error = events_task.exception()
                if error:
                    raise error
                raise SessionReset("events child exited before ready")
            else:
                raise SessionReset("events stream startup timeout")
            ready_task.cancel()
            await asyncio.gather(ready_task, return_exceptions=True)
            ready_task = None
            if not bootstrapped:
                if not self.budget.reserve(len(initial_body)):
                    raise SessionReset("adapter queued-byte budget exhausted")
                try:
                    self.queue.put_nowait((secrets.token_hex(16), initial_body))
                except asyncio.QueueFull as exc:
                    self.budget.release(len(initial_body))
                    raise SessionReset("adapter frame queue exhausted") from exc
            reader_task = asyncio.create_task(self._local_reader(), name="adapter-local-reader")
            sender_task = asyncio.create_task(self._sender(), name="adapter-post-sender")
            tasks.extend([reader_task, sender_task])
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task.cancelled():
                    raise SessionReset("adapter child cancelled")
                error = task.exception()
                if error:
                    raise error
            names = ", ".join(task.get_name() for task in done)
            if reader_task in done:
                if self.drain_end is None:
                    self.drain_end = self.clock() + self.settings.retry_budget
                try:
                    await self._drain_sender(sender_task, self.drain_end)
                except (asyncio.TimeoutError, SessionReset):
                    pass
                raise IntendedLocalEOF
            raise SessionReset(f"adapter child exited: {names}")
        finally:
            self.closed = True
            if ready_task is not None:
                ready_task.cancel()
            for task in tasks:
                task.cancel()
            await asyncio.gather(
                *tasks,
                *((ready_task,) if ready_task is not None else ()),
                return_exceptions=True,
            )
            self._discard_queue()
            try:
                await self._cleanup()
            finally:
                await self.client.close_connection(self.http_connection)
            self.local_writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.local_writer.wait_closed(), 1.0)

    def _discard_queue(self) -> None:
        while True:
            try:
                item = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if item is not None:
                self.budget.release(len(item[1]))

    async def _startup_jitter(self, end: float) -> None:
        if self.settings.startup_jitter_max:
            await self.sleep(min(max(0.0, end - self.clock()), self.uniform(0, self.settings.startup_jitter_max)))
        if self.clock() >= end:
            raise SessionReset("startup jitter exhausted login deadline")

    async def _bootstrap_or_create(self, login_body: bytes) -> bool:
        end = self.clock() + self.settings.retry_budget
        await self._startup_jitter(end)
        request_id = secrets.token_hex(16)
        self.create_may_exist = True
        response = await self._retry_request(
            "POST", self.root + "/bootstrap",
            self.headers(request_id) | {
                "Content-Type": "application/x-ndjson",
                **({"X-Filler-Slot": self.settings.filler_slot} if self.settings.filler_slot else {}),
            },
            login_body, accepted={200, 201}, end=end,
        )
        if response.status in {200, 201}:
            telemetry("protocol_negotiation", mode="bootstrap", status=response.status)
            # The create outcome is now definitive: the exit-time DELETE is
            # reserved for an ambiguous create that may have committed.  A
            # confirmed session must NOT be deleted on exit, because the
            # Cloud recycles containers and a successor incarnation adopts
            # this session; a dying owner's DELETE would kill the live,
            # adopted session out from under it.  An abandoned session is
            # reclaimed by the Gateway lease reaper instead.
            self.create_may_exist = False
            return True
        if (
            response.status == 409
            and self._error_code(response) == "session_already_exists"
        ):
            # The Gateway already holds a live session for this exact identity
            # with our capability. Bootstrap submitted login in the same
            # request, so adopting must not send that login again. Legacy
            # CREATE has no login payload and retains the READY fallback below.
            self.create_may_exist = False
            telemetry("session_adopted", mode="bootstrap", status=409)
            return True
        if response.status == 404:
            # Definitive: this Gateway has no bootstrap route (or no session);
            # the ambiguity is resolved either way before the legacy CREATE.
            self.create_may_exist = False
        if response.status != 404:
            self._raise_error(response, {200, 201})
        # A definitive 404 is the only safe feature-negotiation fallback.  An
        # ambiguous timeout or transient response stays on /bootstrap so that
        # CREATE can never race a bootstrap which may already have committed.
        await self._create(end=end, apply_jitter=False)
        telemetry("protocol_negotiation", mode="legacy_fallback", status=response.status)
        return False

    async def _create(self, end: float | None = None, *, apply_jitter: bool = True) -> None:
        if end is None:
            end = self.clock() + self.settings.retry_budget
        if apply_jitter:
            await self._startup_jitter(end)
        request_id = secrets.token_hex(16)
        self.create_may_exist = True
        response = await self._retry_request(
            "POST", self.root,
            self.headers(request_id) | {
                "Content-Type": "application/json",
                **({"X-Filler-Slot": self.settings.filler_slot} if self.settings.filler_slot else {}),
            },
            CREATE_BODY, accepted={200, 201}, end=end,
        )
        if (
            response.status == 409
            and self._error_code(response) == "session_already_exists"
        ):
            # See _bootstrap_or_create: a live session under this identity is
            # adopted rather than treated as a fatal conflict. The adopted
            # session is lineage-owned; this incarnation must not delete it
            # on exit.
            self.create_may_exist = False
            telemetry("session_adopted", mode="create", status=409)
            return
        self._raise_error(response, {200, 201})
        # Definitive create success: exit must not DELETE (see the bootstrap
        # branch; a successor incarnation may have adopted this session).
        self.create_may_exist = False

    async def _read_local_frame(self, *, initial: bool = False) -> tuple[bytes, dict] | None:
        try:
            line = await self.local_reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            if exc.partial:
                raise SessionReset("unterminated local frame")
            if initial:
                raise SessionReset("local EOF before login")
            return None
        except asyncio.LimitOverrunError as exc:
            raise SessionReset("local frame too large") from exc
        body=line[:-1]
        if body.endswith(b"\r"):body=body[:-1]
        if not body or len(body) > self.settings.max_frame or b"\r" in body or b"\n" in body:
            raise SessionReset("invalid local frame")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionReset("invalid local JSON") from exc
        if not isinstance(value, dict):
            raise SessionReset("local JSON must be an object")
        return body,value

    async def _local_reader(self) -> None:
        while not self.closed:
            frame = await self._read_local_frame()
            if frame is None:
                self.drain_end = self.clock() + self.settings.retry_budget
                await self.queue.put(None)
                return
            body,_value = frame
            await self.events_ready.wait()
            if not self.budget.reserve(len(body)):
                raise SessionReset("adapter queued-byte budget exhausted")
            try:
                self.queue.put_nowait((secrets.token_hex(16), body))
            except asyncio.QueueFull as exc:
                self.budget.release(len(body))
                raise SessionReset("adapter frame queue exhausted") from exc
        await self.queue.put(None)

    async def _drain_sender(self, sender_task: asyncio.Task, drain_end: float) -> None:
        remaining = drain_end - self.clock()
        if remaining <= 0:
            raise asyncio.TimeoutError
        await asyncio.wait_for(asyncio.shield(sender_task), remaining)

    async def _sender(self) -> None:
        next_lease_at = self.clock() + self.settings.lease_interval
        while True:
            remaining = next_lease_at - self.clock()
            if remaining <= 0:
                item = None
                lease_due = True
            else:
                try:
                    item = await asyncio.wait_for(self.queue.get(), remaining)
                    lease_due = False
                except asyncio.TimeoutError:
                    item = None
                    lease_due = True
            if lease_due:
                response = await self._retry_request(
                    "POST", self.root + "/lease",
                    self.headers(secrets.token_hex(16)) | {"Content-Type": "application/json"},
                    LEASE_BODY, accepted={200, 204}, end=self.drain_end,
                )
                self._raise_error(response, {200, 204})
                next_lease_at = self.clock() + self.settings.lease_interval
                continue
            if item is None:
                return
            request_id, exact_body = item
            try:
                await self.events_ready.wait()
                response = await self._retry_request(
                    "POST", self.root + "/frames",
                    self.headers(request_id) | {"Content-Type": "application/x-ndjson"}, exact_body,
                    accepted={200, 202}, end=self.drain_end,
                )
                self._raise_error(response, {200, 202})
                next_lease_at = self.clock() + self.settings.lease_interval
            finally:
                self.budget.release(len(exact_body))

    @staticmethod
    def _error_code(response: Response) -> str:
        with contextlib.suppress(Exception):
            value = json.loads(response.body)
            if isinstance(value, dict):
                return str(value.get("error", ""))
        return ""

    @staticmethod
    def _retry_after(raw: str) -> float | None:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return None
        return value if math.isfinite(value) and value >= 0 else None

    async def _retry_request(self, method: str, path: str, headers: dict[str, str], body: bytes, accepted: set[int], end: float | None = None) -> Response:
        async with self.post_lock:
            return await self._retry_request_locked(method, path, headers, body, accepted, end)

    async def _retry_request_locked(self, method: str, path: str, headers: dict[str, str], body: bytes, accepted: set[int], end: float | None = None) -> Response:
        base = 0.1
        last_error: BaseException | None = None
        if end is None:
            end = self.clock() + self.settings.retry_budget
        for attempt in range(1, self.settings.retry_limit + 1):
            if self.clock() >= end:
                break
            status: int | None = None
            code = ""
            try:
                response = await self.client.request(method, path, headers, body, end=end, connection=self.http_connection)
                last_error = None
                status = response.status
                code = self._error_code(response)
                if response.status in accepted or response.status not in {429, 502, 503, 504}:
                    if attempt > 1 or not path.endswith("/frames"):
                        telemetry("http_attempt", method=method, attempt=attempt, status=status, error_code=code, outcome="complete")
                    return response
                retry_after = self._retry_after(response.headers.get("retry-after", "")) if status == 429 else None
                wait = retry_after + self.uniform(0, 1.0) if retry_after is not None else self.uniform(0.5 * base, 1.5 * base)
                if code == "create_paused":
                    wait = PAUSE_RETRY_SECONDS + self.uniform(0, PAUSE_RETRY_JITTER_SECONDS)
                    end = max(end, self.clock() + wait + 1.0)
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, HTTPProtocolError) as exc:
                last_error = exc
                wait = self.uniform(0.5 * base, 1.5 * base)
            telemetry("http_retry", method=method, attempt=attempt, status=status, error_code=code, error_type=type(last_error).__name__ if last_error else "")
            if attempt >= self.settings.retry_limit:
                break
            remaining = end - self.clock()
            if remaining <= 0:
                break
            await self.sleep(min(remaining, wait))
            base = min(5.0, 2 * base)
        raise SessionReset(f"HTTP retry budget exhausted: {last_error or 'retryable response'}")

    def _raise_error(self, response: Response, accepted: set[int]) -> None:
        if response.status in accepted:
            return
        code = ""
        with contextlib.suppress(Exception):
            value = json.loads(response.body)
            if isinstance(value, dict):
                code = str(value.get("error", ""))
        raise SessionReset(f"gateway rejected session: HTTP {response.status} {code}".strip())

    async def _events(self) -> None:
        if self.settings.event_poll_enabled:
            await self._event_poll()
            return
        await self._event_stream()

    async def _event_poll(self) -> None:
        while not self.closed:
            response = await self._retry_request(
                "GET", self.root + f"/events?after={self.cursor}&poll=1",
                self.headers() | {"Accept": "application/x-ndjson"}, b"",
                accepted={200},
            )
            self._raise_error(response, {200})
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/x-ndjson":
                raise HTTPProtocolError("events response has invalid content type")
            self.events_ready.set()
            for raw in response.body.splitlines():
                if raw.strip():
                    await self._event(raw)
            if self.closed:
                return
            await self.sleep(self.settings.event_poll_interval)

    async def _event_stream(self) -> None:
        base = 0.1
        recovery_end: float | None = None
        reconnect_attempt = 0
        while not self.closed:
            incarnation = secrets.token_hex(16)
            path = self.root + f"/events?after={self.cursor}"
            headers = self.headers() | {
                "Accept": "application/x-ndjson",
                "X-Stream-Incarnation": incarnation,
            }
            writer: asyncio.StreamWriter | None = None
            failure: BaseException | None = None
            connected_at: float | None = None
            valid_event_seen = False
            try:
                async with self.reconnect_gate.admission():
                    reader, writer, head = await self.client.open_request("GET", path, headers, end=recovery_end)
                if head.status != 200:
                    body = await self.client._read_body(reader, head.headers, end=recovery_end)
                    if head.status in {429, 502, 503, 504}:
                        raise OSError(f"transient events status {head.status}")
                    self._raise_error(Response(head.status, head.headers, body), {200})
                content_type = head.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/x-ndjson":
                    raise HTTPProtocolError("events response has invalid content type")
                connected_at = self.clock()
                self.events_ready.set()
                buffered = bytearray()
                async for chunk in self.client.iter_event_body(reader, head.headers, end=recovery_end):
                    buffered.extend(chunk)
                    while b"\n" in buffered:
                        raw, _, remainder = buffered.partition(b"\n")
                        buffered = bytearray(remainder)
                        if len(raw) > max_event_line_bytes(self.settings.max_frame, self.generation):
                            raise HTTPProtocolError("events line too large")
                        if raw.strip():
                            await self._event(raw[:-1] if raw.endswith(b"\r") else raw)
                            valid_event_seen = True
                    if len(buffered) > max_event_line_bytes(self.settings.max_frame, self.generation):
                        raise HTTPProtocolError("events line too large")
                if buffered.strip():
                    raise HTTPProtocolError("unterminated event")
                failure = OSError("events stream ended")
            except SessionReset:
                raise
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
                failure = exc
            finally:
                self.events_ready.clear()
                if writer is not None:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(writer.wait_closed(), 1.0)
            if self.closed:
                return
            now = self.clock()
            if valid_event_seen and connected_at is not None and now - connected_at >= self.settings.recovery_stable:
                recovery_end = None
                base = 0.1
                reconnect_attempt = 0
            if recovery_end is None:
                recovery_end = now + self.settings.recovery_budget
            if now >= recovery_end:
                raise SessionReset("events recovery budget exhausted") from failure
            reconnect_attempt += 1
            telemetry("event_reconnect", attempt=reconnect_attempt, cursor=self.cursor, error_type=type(failure).__name__ if failure else "stream_end")
            await self.sleep(min(recovery_end - now, self.uniform(0.5 * base, 1.5 * base)))
            base = min(5.0, 2 * base)

    async def _event(self, raw: bytes) -> None:
        try:
            event = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionReset("invalid event JSON") from exc
        if not isinstance(event, dict) or event.get("generation") != self.generation:
            raise SessionReset("event generation mismatch")
        kind = event.get("type")
        if kind == "heartbeat":
            return
        if kind == "reset":
            raise SessionReset(str(event.get("reason", "gateway reset")))
        if kind != "stratum" or not isinstance(event.get("server_seq"), int):
            raise SessionReset("invalid event")
        seq = event["server_seq"]
        if seq <= self.cursor:
            return
        if seq != self.cursor + 1:
            raise SessionReset("event cursor gap")
        frame = event.get("frame")
        if not isinstance(frame, dict):
            raise SessionReset("invalid stratum event")
        encoded = json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > self.settings.max_frame:
            raise SessionReset("stratum event too large")
        try:
            self.local_writer.write(encoded + b"\n")
            await asyncio.wait_for(self.local_writer.drain(), self.settings.local_write_timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            # The write may already be partially visible locally.  Reconnecting
            # Events with the same cursor could replay and duplicate it, so a
            # local sink failure is terminal for this Session.
            raise SessionReset("local Stratum write failed") from exc
        self.cursor = seq

    async def _cleanup(self) -> None:
        if not self.create_may_exist or self.cleanup_started:
            return
        self.cleanup_started = True
        await self._delete()

    async def _delete(self) -> None:
        end = self.clock() + min(self.settings.http_timeout, 10.0)
        try:
            response = await self._retry_request(
                "DELETE",
                self.root,
                self.headers(),
                b"",
                accepted={200},
                end=end,
            )
            self._raise_error(response, {200})
            try:
                payload = json.loads(response.body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SessionReset("gateway DELETE response is not JSON") from exc
            if (
                not isinstance(payload, dict)
                or payload.get("ok") is not True
                or payload.get("closed") is not True
            ):
                raise SessionReset("gateway DELETE was not authoritative")
            telemetry("delete", outcome="completed", status=response.status)
        except Exception as exc:
            telemetry("delete", outcome="failed", error_type=type(exc).__name__)


async def serve(settings: Settings = SETTINGS) -> None:
    client = HTTPClient(settings.bridge_url, settings)
    budget = ResourceBudget(settings.max_queued_bytes)
    reconnect_gate = ReconnectGate(settings.max_event_connects, settings.reconnect_interval)
    sessions: set[asyncio.Task[None]] = set()
    controlled_one_shot = bool(settings.session_id)
    one_shot_started = False
    one_shot_finished = asyncio.Event()

    async def accepted(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal one_shot_started
        if controlled_one_shot and one_shot_started:
            telemetry("admission", outcome="one_shot_busy", active_sessions=len(sessions))
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        if controlled_one_shot:
            one_shot_started = True
        task = asyncio.current_task()
        if task is not None:
            sessions.add(task)
        telemetry("admission", outcome="accepted", active_sessions=len(sessions))
        close_reason = "intended_local_eof"
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            await AdapterSession(reader, writer, client, budget, reconnect_gate, settings=settings).run()
        except IntendedLocalEOF:
            close_reason = "intended_local_eof"
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except Exception as exc:
            close_reason = f"{type(exc).__name__}:{exc}"
            telemetry("session_error", error_type=type(exc).__name__, error=str(exc))
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        finally:
            if task is not None:
                sessions.discard(task)
            telemetry("close", reason=close_reason, active_sessions=len(sessions))
            if controlled_one_shot:
                one_shot_finished.set()

    server = await asyncio.start_server(accepted, settings.listen_host, settings.listen_port, limit=settings.max_frame + 2)
    if settings.ready_file:
        ready_path = os.path.abspath(settings.ready_file)
        temporary = ready_path + f".{os.getpid()}.tmp"
        with open(temporary, "w", encoding="ascii") as handle:
            handle.write(f"{os.getpid()}\n")
        os.replace(temporary, ready_path)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, stop.set)
    try:
        async with server:
            waiter = asyncio.create_task(server.serve_forever())
            stopper = asyncio.create_task(stop.wait())
            one_shot_waiter = (
                asyncio.create_task(one_shot_finished.wait())
                if controlled_one_shot
                else None
            )
            waiters = (waiter, stopper, *((one_shot_waiter,) if one_shot_waiter else ()))
            done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            if waiter in done and not waiter.cancelled():
                waiter.result()
            server.close()
            await server.wait_closed()
            waiter.cancel()
            stopper.cancel()
            if one_shot_waiter is not None:
                one_shot_waiter.cancel()
            for task in tuple(sessions):
                task.cancel()
            await asyncio.gather(*waiters, *tuple(sessions), return_exceptions=True)
    finally:
        if settings.ready_file:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.abspath(settings.ready_file))


def main() -> int:
    try:
        asyncio.run(serve())
    except (ValueError, OSError) as exc:
        print(f"bridge adapter startup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
