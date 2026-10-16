#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mindustry Forwarder - Encoder (client side)

Listens on the Mindustry port (TCP + UDP). For each client session, opens a
TCP tunnel to the remote decoder, sends a context header describing the real
client address, then relays traffic.

Context header (big-endian), must match decoder/cmd/decoder_server.go:

    flags   : 1 byte   bit0 = IS_TCP, bit7 = IS_IPV6
    port    : 2 bytes  client source port (uint16 BE)
    address : 4 bytes (IPv4) or 16 bytes (IPv6)

After the header:
    TCP session : raw byte stream (no framing)
    UDP session : repeated frames of uint16 BE length + payload

Python 3.8+ / Windows x64 / standard library only.
"""

from __future__ import annotations

DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 6567
DEFAULT_SERVER_HOST = "10.22.33.1"
# DEFAULT_SERVER_HOST = "192.168.137.33"
DEFAULT_SERVER_PORT = 6568

import argparse
import asyncio
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# constants (keep in sync with decoder)
# ---------------------------------------------------------------------------

IS_TCP_MASK = 1
IS_IPV6_MASK = 128

DEFAULT_TIMEOUT = 5.0
DEFAULT_UDP_IDLE = 120.0
DEFAULT_BACKLOG = 128

BUFFER_SIZE = 65535
# UDP payload max after 2-byte length prefix on a single TCP write
UDP_MAX_PAYLOAD = 65535
# Max datagrams buffered while the decoder tunnel is still connecting.
UDP_CONNECT_QUEUE = 64
# Soft cap on queued outbound frames after the tunnel is up (drop oldest).
UDP_OUTBOUND_QUEUE = 256
UDP_SOCKET_BUF = 4 * 1024 * 1024

IpAddr = Union[IPv4Address, IPv6Address]
ClientKey = Tuple[str, int]

# ---------------------------------------------------------------------------
# logging (UTC, mirrors decoder prefix style)
# ---------------------------------------------------------------------------

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="[Mindustry Forwarder Client] UTC::%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("encoder")


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Context:
    ip: IpAddr
    port: int
    is_tcp: bool

    @property
    def is_ipv6(self) -> bool:
        return isinstance(self.ip, IPv6Address)

    def __str__(self) -> str:
        proto = "TCP" if self.is_tcp else "UDP"
        return "[{} {}:{}]".format(proto, self.ip, self.port)

    def pack(self) -> bytes:
        flags = 0
        if self.is_tcp:
            flags |= IS_TCP_MASK
        if self.is_ipv6:
            flags |= IS_IPV6_MASK
        return struct.pack("!BH", flags, self.port & 0xFFFF) + self.ip.packed


def context_from_peer(peername, is_tcp: bool) -> Context:
    """Build Context from a socket peername ``(host, port, ...)``."""
    host = peername[0]
    port = int(peername[1])
    addr = ip_address(host)
    # collapse IPv4-mapped IPv6 (:ffff:x.x.x.x) to plain IPv4
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return Context(ip=addr, port=port, is_tcp=is_tcp)


def normalize_peer_host(host: str) -> str:
    try:
        addr = ip_address(host)
    except ValueError:
        return host
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return host


# ---------------------------------------------------------------------------
# socket helpers
# ---------------------------------------------------------------------------


def silence_udp_connreset(sock: socket.socket) -> None:
    """
    Windows: after UDP traffic, ICMP Port Unreachable may surface as
    WSAECONNRESET (WinError 10054) on recv/recvfrom. Disable that so a single
    unreachable reply does not tear down the relay.
    """
    sio = getattr(socket, "SIO_UDP_CONNRESET", None)
    if sio is None:
        return
    try:
        sock.ioctl(sio, False)
    except (AttributeError, OSError, TypeError, ValueError):
        try:
            sock.ioctl(sio, bytes([0, 0, 0, 0]))
        except (AttributeError, OSError, TypeError, ValueError):
            pass


def tune_tcp_socket(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


def tune_udp_socket(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    silence_udp_connreset(sock)
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_SOCKET_BUF)
        except OSError:
            pass


async def open_tunnel(
    server_host: str,
    server_port: int,
    timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=server_host, port=server_port),
        timeout=timeout,
    )
    tune_tcp_socket(writer.get_extra_info("socket"))
    return reader, writer


# Connection teardown noise on Windows includes ConnectionAbortedError
# (WinError 1236) and ConnectionResetError (10054); treat all as normal.
_PIPE_CONN_ERRORS = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    ConnectionError,
    OSError,
    EOFError,
)


async def close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        return
    try:
        await writer.wait_closed()
    except Exception:
        # Windows Proactor: wait_closed can surface WinError 1236 / 10054
        # after the peer already aborted the socket.
        pass


async def pipe_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    label: str,
) -> None:
    """Raw bidirectional-side TCP pipe (no framing).

    Connection errors are swallowed so background tasks finish cleanly
    without ``Task exception was never retrieved`` on Windows.
    """
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        raise
    except _PIPE_CONN_ERRORS as exc:
        logger.debug("%s pipe closed: %s", label, exc)
    finally:
        try:
            if not writer.is_closing() and writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


def _task_done_log(task: asyncio.Future) -> None:
    """Retrieve task result so failed background pipes are not left unawaited."""
    try:
        exc = task.exception()
    except (asyncio.CancelledError, asyncio.InvalidStateError):
        return
    if exc is not None and not isinstance(exc, asyncio.CancelledError):
        logger.debug("background task error: %s", exc)


async def read_udp_frame(reader: asyncio.StreamReader) -> Optional[bytes]:
    """
    Read one length-prefixed UDP frame from the tunnel.
    Returns None on clean EOF before a frame starts.
    """
    try:
        hdr = await reader.readexactly(2)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise
    (length,) = struct.unpack("!H", hdr)
    if length == 0:
        return b""
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise ConnectionError("truncated UDP frame (want {} bytes)".format(length))


def pack_udp_frame(payload: bytes) -> bytes:
    if len(payload) > UDP_MAX_PAYLOAD:
        raise ValueError("UDP payload too large: {}".format(len(payload)))
    return struct.pack("!H", len(payload)) + payload


# ---------------------------------------------------------------------------
# TCP path
# ---------------------------------------------------------------------------


async def tcp_client_handler(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    server_host: str,
    server_port: int,
    timeout: float,
) -> None:
    peer = client_writer.get_extra_info("peername")
    if not peer:
        await close_writer(client_writer)
        return

    ctx = context_from_peer(peer, is_tcp=True)
    tunnel_reader = None  # type: Optional[asyncio.StreamReader]
    tunnel_writer = None  # type: Optional[asyncio.StreamWriter]
    c2s_task = None  # type: Optional[asyncio.Future]

    try:
        try:
            tunnel_reader, tunnel_writer = await open_tunnel(server_host, server_port, timeout)
        except (asyncio.TimeoutError, OSError) as exc:
            logger.error("%s cannot connect to decoder: %s", ctx, exc)
            return

        tunnel_writer.write(ctx.pack())
        await tunnel_writer.drain()
        logger.info("%s TCP session opened -> %s:%s", ctx, server_host, server_port)

        c2s_task = asyncio.ensure_future(
            pipe_stream(client_reader, tunnel_writer, "{} c2s".format(ctx))
        )
        c2s_task.add_done_callback(_task_done_log)
        try:
            await pipe_stream(tunnel_reader, client_writer, "{} s2c".format(ctx))
        except asyncio.CancelledError:
            raise
        except _PIPE_CONN_ERRORS:
            pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("%s TCP session error: %s", ctx, exc)
    finally:
        if c2s_task is not None:
            if not c2s_task.done():
                c2s_task.cancel()
            try:
                await c2s_task
            except (asyncio.CancelledError, Exception):
                pass
        await close_writer(tunnel_writer)
        await close_writer(client_writer)
        logger.info("%s TCP session closed", ctx)


async def run_tcp_server(
    listen_host: str,
    listen_port: int,
    server_host: str,
    server_port: int,
    timeout: float,
    backlog: int,
) -> asyncio.AbstractServer:
    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await tcp_client_handler(reader, writer, server_host, server_port, timeout)

    server = await asyncio.start_server(
        _handler,
        host=listen_host,
        port=listen_port,
        backlog=backlog,
        reuse_address=True,
    )
    for sock in server.sockets or []:
        logger.info("start to listen TCP: `%s`", sock.getsockname())
    return server


# ---------------------------------------------------------------------------
# UDP path — one TCP tunnel per client (ip, port), length-prefixed frames
#
# Critical: all tunnel writes for a session go through a single writer task
# so concurrent datagram_received callbacks cannot interleave length-prefix
# frames (that desyncs the decoder and kills UDP entirely).
# ---------------------------------------------------------------------------


class UdpSession(object):
    """Relays UDP datagrams for one client endpoint via a TCP tunnel."""

    __slots__ = (
        "key",
        "ctx",
        "transport",
        "server_host",
        "server_port",
        "timeout",
        "idle_timeout",
        "tunnel_reader",
        "tunnel_writer",
        "reader_task",
        "writer_task",
        "out_queue",
        "last_active",
        "closed",
        "starting",
        "pending",
    )

    def __init__(
        self,
        key,  # type: ClientKey
        ctx,  # type: Context
        transport,  # type: asyncio.DatagramTransport
        server_host,  # type: str
        server_port,  # type: int
        timeout,  # type: float
        idle_timeout,  # type: float
    ):
        # type: (...) -> None
        self.key = key
        self.ctx = ctx
        self.transport = transport
        self.server_host = server_host
        self.server_port = server_port
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.tunnel_reader = None  # type: Optional[asyncio.StreamReader]
        self.tunnel_writer = None  # type: Optional[asyncio.StreamWriter]
        self.reader_task = None  # type: Optional[asyncio.Task]
        self.writer_task = None  # type: Optional[asyncio.Task]
        self.out_queue = asyncio.Queue(maxsize=UDP_OUTBOUND_QUEUE)
        self.last_active = time.monotonic()
        self.closed = False
        self.starting = False
        self.pending = []  # type: list  # datagrams while tunnel connects

    def enqueue(self, data):
        # type: (bytes) -> None
        """Called from the datagram callback (same thread as the event loop)."""
        if not data or self.closed:
            return
        self.last_active = time.monotonic()

        if self.tunnel_writer is None:
            # Still connecting: buffer a few packets, then start the tunnel once.
            if len(self.pending) < UDP_CONNECT_QUEUE:
                self.pending.append(data)
            else:
                # Drop oldest so the newest (often more useful) survives.
                self.pending.pop(0)
                self.pending.append(data)
            if not self.starting:
                self.starting = True
                loop = asyncio.get_event_loop()
                loop.create_task(self._start())
            return

        self._queue_put(data)

    def _queue_put(self, data):
        # type: (bytes) -> None
        try:
            self.out_queue.put_nowait(data)
        except asyncio.QueueFull:
            try:
                self.out_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self.out_queue.put_nowait(data)
            except asyncio.QueueFull:
                pass

    async def _start(self):
        # type: () -> None
        try:
            if self.closed:
                return
            try:
                reader, writer = await open_tunnel(
                    self.server_host, self.server_port, self.timeout
                )
            except (asyncio.TimeoutError, OSError) as exc:
                logger.error("%s cannot connect to decoder: %s", self.ctx, exc)
                await self.close()
                return

            writer.write(self.ctx.pack())
            try:
                await writer.drain()
            except OSError as exc:
                logger.error("%s cannot write context: %s", self.ctx, exc)
                await close_writer(writer)
                await self.close()
                return

            self.tunnel_reader = reader
            self.tunnel_writer = writer

            # Flush packets buffered during connect (in arrival order).
            pending = self.pending
            self.pending = []
            for pkt in pending:
                self._queue_put(pkt)

            self.reader_task = asyncio.ensure_future(self._read_tunnel())
            self.reader_task.add_done_callback(_task_done_log)
            self.writer_task = asyncio.ensure_future(self._write_tunnel())
            self.writer_task.add_done_callback(_task_done_log)
            logger.info(
                "%s UDP session opened -> %s:%s",
                self.ctx,
                self.server_host,
                self.server_port,
            )
        finally:
            self.starting = False

    async def _write_tunnel(self):
        # type: () -> None
        """Single writer: serializes length-prefixed frames onto the tunnel."""
        writer = self.tunnel_writer
        if writer is None:
            return
        try:
            while not self.closed:
                try:
                    data = await asyncio.wait_for(
                        self.out_queue.get(),
                        timeout=self.idle_timeout,
                    )
                except asyncio.TimeoutError:
                    if time.monotonic() - self.last_active >= self.idle_timeout:
                        logger.info("%s UDP session idle timeout (writer)", self.ctx)
                        break
                    continue
                if data is None:
                    break
                try:
                    writer.write(pack_udp_frame(data))
                    await writer.drain()
                except (OSError, ValueError) as exc:
                    logger.error("%s UDP c2s write failed: %s", self.ctx, exc)
                    break
                self.last_active = time.monotonic()
        except asyncio.CancelledError:
            pass
        except _PIPE_CONN_ERRORS as exc:
            logger.debug("%s UDP writer closed: %s", self.ctx, exc)
        finally:
            await self.close()

    async def _read_tunnel(self):
        # type: () -> None
        reader = self.tunnel_reader
        if reader is None:
            return
        addr = self.key
        try:
            while not self.closed:
                try:
                    payload = await asyncio.wait_for(
                        read_udp_frame(reader),
                        timeout=self.idle_timeout,
                    )
                except asyncio.TimeoutError:
                    if time.monotonic() - self.last_active >= self.idle_timeout:
                        logger.info("%s UDP session idle timeout (reader)", self.ctx)
                        break
                    continue
                except asyncio.IncompleteReadError as exc:
                    if not self.closed and exc.partial:
                        logger.debug("%s UDP tunnel truncated frame", self.ctx)
                    break
                except _PIPE_CONN_ERRORS as exc:
                    if not self.closed:
                        logger.debug("%s UDP tunnel read end: %s", self.ctx, exc)
                    break

                if payload is None:
                    break

                self.last_active = time.monotonic()
                try:
                    self.transport.sendto(payload, addr)
                except OSError as exc:
                    # Windows may raise 10054 here; keep the session unless fatal.
                    logger.debug("%s UDP s2c send failed: %s", self.ctx, exc)
                    continue
        except asyncio.CancelledError:
            pass
        except _PIPE_CONN_ERRORS as exc:
            logger.debug("%s UDP tunnel closed: %s", self.ctx, exc)
        finally:
            await self.close()

    async def close(self):
        # type: () -> None
        if self.closed:
            return
        self.closed = True
        self.pending = []
        # Unblock writer waiting on queue
        try:
            self.out_queue.put_nowait(None)
        except Exception:
            pass

        current = asyncio.current_task() if hasattr(asyncio, "current_task") else None
        for task in (self.reader_task, self.writer_task):
            if task is None or task is current or task.done():
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self.reader_task = None
        self.writer_task = None

        writer = self.tunnel_writer
        self.tunnel_writer = None
        self.tunnel_reader = None
        await close_writer(writer)
        logger.info("%s UDP session closed", self.ctx)


class UdpRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, server_host, server_port, timeout, idle_timeout):
        # type: (str, int, float, float) -> None
        self.server_host = server_host
        self.server_port = server_port
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.transport = None  # type: Optional[asyncio.DatagramTransport]
        self.sessions = {}  # type: Dict[ClientKey, UdpSession]
        self._reaper_task = None  # type: Optional[asyncio.Task]
        self._loop = None  # type: Optional[asyncio.AbstractEventLoop]

    def connection_made(self, transport):
        # type: (asyncio.BaseTransport) -> None
        self.transport = transport  # type: ignore[assignment]
        self._loop = asyncio.get_event_loop()
        sock = transport.get_extra_info("socket")
        tune_udp_socket(sock)
        sockname = transport.get_extra_info("sockname")
        logger.info("start to listen UDP: `%s`", sockname)
        self._reaper_task = self._loop.create_task(self._reap_idle())

    def datagram_received(self, data, addr):
        # type: (bytes, tuple) -> None
        if self.transport is None or not data:
            return

        host = normalize_peer_host(addr[0])
        port = int(addr[1])
        key = (host, port)  # type: ClientKey

        session = self.sessions.get(key)
        if session is None or session.closed:
            ctx = context_from_peer((host, port), is_tcp=False)
            session = UdpSession(
                key=key,
                ctx=ctx,
                transport=self.transport,
                server_host=self.server_host,
                server_port=self.server_port,
                timeout=self.timeout,
                idle_timeout=self.idle_timeout,
            )
            self.sessions[key] = session

        # Synchronous enqueue — no per-datagram task (avoids write races).
        session.enqueue(data)

    def error_received(self, exc):
        # type: (Exception) -> None
        # Windows may still deliver ICMP-related errors here; keep listening.
        logger.debug("UDP endpoint error: %s", exc)

    def connection_lost(self, exc):
        # type: (Optional[Exception]) -> None
        if exc:
            logger.error("UDP endpoint lost: %s", exc)
        if self._reaper_task is not None:
            self._reaper_task.cancel()

    async def _reap_idle(self):
        # type: () -> None
        try:
            interval = min(5.0, max(1.0, self.idle_timeout / 4.0))
            while True:
                await asyncio.sleep(interval)
                now = time.monotonic()
                dead = [
                    key
                    for key, sess in list(self.sessions.items())
                    if sess.closed or (now - sess.last_active >= self.idle_timeout)
                ]
                for key in dead:
                    sess = self.sessions.pop(key, None)
                    if sess is not None and not sess.closed:
                        await sess.close()
        except asyncio.CancelledError:
            pass

    async def close_all(self):
        # type: () -> None
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except (asyncio.CancelledError, Exception):
                pass
        sessions = list(self.sessions.values())
        self.sessions.clear()
        for sess in sessions:
            await sess.close()
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass


async def run_udp_endpoint(
    listen_host,
    listen_port,
    server_host,
    server_port,
    timeout,
    idle_timeout,
):
    # type: (str, int, str, int, float, float) -> Tuple[asyncio.DatagramTransport, UdpRelayProtocol]
    loop = asyncio.get_event_loop()

    def _factory():
        # type: () -> UdpRelayProtocol
        return UdpRelayProtocol(server_host, server_port, timeout, idle_timeout)

    # Python 3.8+ rejects reuse_address on create_datagram_endpoint (SO_REUSEPORT
    # security concern). Pre-bind a socket with SO_REUSEADDR ourselves instead.
    family = (
        socket.AF_INET6
        if ":" in listen_host and not listen_host.startswith("::ffff:")
        else socket.AF_INET
    )
    # Dual-stack / host detection: let getaddrinfo decide when host is not literal-friendly.
    try:
        infos = socket.getaddrinfo(
            listen_host, listen_port, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
        )
        family = infos[0][0]
    except socket.gaierror:
        pass

    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        tune_udp_socket(sock)
        sock.bind((listen_host, listen_port))
        sock.setblocking(False)
        transport, protocol = await loop.create_datagram_endpoint(_factory, sock=sock)
    except Exception:
        sock.close()
        raise

    return transport, protocol  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------


def parse_args(argv=None):
    # type: (Optional[list]) -> argparse.Namespace
    parser = argparse.ArgumentParser(
        description=("Mindustry Forwarder Encoder — tunnel local clients to remote decoder"),
    )
    parser.add_argument(
        "-l",
        "--listen",
        default="{}:{}".format(DEFAULT_LISTEN_HOST, DEFAULT_LISTEN_PORT),
        help="local listen host:port for Mindustry clients (default: %(default)s)",
    )
    parser.add_argument(
        "-s",
        "--server",
        default="{}:{}".format(DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT),
        help="decoder host:port (default: %(default)s)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="connect timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--udp-idle",
        type=float,
        default=DEFAULT_UDP_IDLE,
        help="UDP session idle timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=DEFAULT_BACKLOG,
        help="TCP listen backlog (default: %(default)s)",
    )
    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="only listen TCP (skip UDP)",
    )
    parser.add_argument(
        "--udp-only",
        action="store_true",
        help="only listen UDP (skip TCP)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="debug logging",
    )
    return parser.parse_args(argv)


def split_host_port(value, default_host, default_port):
    # type: (str, str, int) -> Tuple[str, int]
    value = (value or "").strip()
    if not value:
        return default_host, default_port

    # [ipv6]:port
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("invalid address: {}".format(value))
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        if rest:
            raise ValueError("invalid address: {}".format(value))
        return host, default_port

    # :port
    if value.startswith(":"):
        return default_host, int(value[1:])

    # bare port
    if value.isdigit():
        return default_host, int(value)

    # host:port (exactly one colon → IPv4 host or hostname)
    if value.count(":") == 1:
        host, _, port_s = value.partition(":")
        host = host if host else default_host
        port = int(port_s) if port_s else default_port
        return host, port

    # bare host / bare ipv6 without port
    return value, default_port


async def amain(args):
    # type: (argparse.Namespace) -> None
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    try:
        listen_host, listen_port = split_host_port(
            args.listen, DEFAULT_LISTEN_HOST, DEFAULT_LISTEN_PORT
        )
        server_host, server_port = split_host_port(
            args.server, DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT
        )
    except ValueError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    if not (0 < listen_port <= 65535):
        logger.error("invalid listen port: %s", listen_port)
        sys.exit(1)
    if not (0 < server_port <= 65535):
        logger.error("invalid server port: %s", server_port)
        sys.exit(1)
    if args.timeout <= 0:
        logger.error("invalid timeout: %s", args.timeout)
        sys.exit(1)
    if args.udp_idle <= 0:
        logger.error("invalid udp-idle: %s", args.udp_idle)
        sys.exit(1)

    do_tcp = not args.udp_only
    do_udp = not args.tcp_only
    if not do_tcp and not do_udp:
        logger.error("both --tcp-only and --udp-only set")
        sys.exit(1)

    logger.info(
        "encoder starting; listen=%s:%s decoder=%s:%s timeout=%ss",
        listen_host,
        listen_port,
        server_host,
        server_port,
        args.timeout,
    )

    tcp_server = None  # type: Optional[asyncio.AbstractServer]
    udp_transport = None  # type: Optional[asyncio.DatagramTransport]
    udp_protocol = None  # type: Optional[UdpRelayProtocol]

    stop_event = asyncio.Event()

    try:
        if do_tcp:
            tcp_server = await run_tcp_server(
                listen_host,
                listen_port,
                server_host,
                server_port,
                args.timeout,
                args.backlog,
            )
        if do_udp:
            udp_transport, udp_protocol = await run_udp_endpoint(
                listen_host,
                listen_port,
                server_host,
                server_port,
                args.timeout,
                args.udp_idle,
            )

        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        if udp_protocol is not None:
            await udp_protocol.close_all()
        elif udp_transport is not None:
            udp_transport.close()
        if tcp_server is not None:
            tcp_server.close()
            await tcp_server.wait_closed()


def main(argv=None):
    # type: (Optional[list]) -> None
    args = parse_args(argv)
    try:
        # asyncio.run is 3.7+
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        logger.info("shutting down")


if __name__ == "__main__":
    main()
