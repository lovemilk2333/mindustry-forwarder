#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive test client for the echo server / forwarder chain.

Commands (interactive prompt):
    t <msg>   / tcp <msg>    send <msg> over TCP, print reply
    u <msg>   / udp <msg>    send <msg> over UDP, print reply
    host <h>                 set target host
    port <p>                 set target port
    target <host:port>       set target host and port
    timeout <sec>            set recv timeout
    help                     show this help
    quit / exit / q          leave

Bare lines without a known verb are treated as TCP messages
(same as ``t <line>``).

Default target: 127.0.0.1:6567 (encoder / Mindustry client port).
Point at 6568 to talk to tests/server.py directly.

Python 3.8+ / stdlib only.
"""

from __future__ import annotations

import argparse
import select
import socket
import sys
import time
from typing import Optional, Tuple

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6567
DEFAULT_TIMEOUT = 3.0
BUFFER_SIZE = 65535

HELP_TEXT = """\
commands:
  t <msg>  | tcp <msg>     send via TCP
  u <msg>  | udp <msg>     send via UDP
  host <h>                 set target host
  port <p>                 set target port
  target <host:port>       set target
  timeout <sec>            recv timeout (seconds)
  help                     this help
  quit | exit | q          exit
  <msg>                    same as tcp <msg>
"""


class ClientState(object):
    def __init__(self, host, port, timeout):
        # type: (str, int, float) -> None
        self.host = host
        self.port = port
        self.timeout = timeout
        # keep one TCP connection across ``t`` commands until it drops
        self._tcp = None  # type: Optional[socket.socket]

    @property
    def target(self):
        # type: () -> str
        return "{}:{}".format(self.host, self.port)

    def close_tcp(self):
        # type: () -> None
        if self._tcp is not None:
            try:
                self._tcp.close()
            except OSError:
                pass
            self._tcp = None

    def get_tcp(self):
        # type: () -> socket.socket
        if self._tcp is not None:
            return self._tcp
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        self._tcp = sock
        print("[tcp] connected to {}".format(self.target))
        return sock


def silence_udp_connreset(sock):
    # type: (socket.socket) -> None
    sio = getattr(socket, "SIO_UDP_CONNRESET", None)
    if sio is None:
        return
    try:
        sock.ioctl(sio, False)
    except (AttributeError, OSError, TypeError, ValueError):
        pass


def recv_some(sock, timeout):
    # type: (socket.socket, float) -> bytes
    """Read whatever is available within timeout (may be multiple chunks)."""
    sock.settimeout(timeout)
    chunks = []
    deadline = time.monotonic() + timeout
    try:
        first = sock.recv(BUFFER_SIZE)
        if not first:
            return b""
        chunks.append(first)
    except socket.timeout:
        return b""
    except OSError as exc:
        raise exc

    # drain a little more if it arrives immediately (TCP may segment)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            ready, _, _ = select.select([sock], [], [], min(0.05, remaining))
        except (ValueError, OSError):
            break
        if not ready:
            break
        try:
            sock.settimeout(0.05)
            more = sock.recv(BUFFER_SIZE)
        except (socket.timeout, OSError):
            break
        if not more:
            break
        chunks.append(more)
    return b"".join(chunks)


def send_tcp(state, message):
    # type: (ClientState, str) -> None
    payload = message.encode("utf-8")
    try:
        sock = state.get_tcp()
        sock.sendall(payload)
        data = recv_some(sock, state.timeout)
        if not data:
            print("[tcp] (no reply / connection closed)")
            state.close_tcp()
            return
        print_reply("tcp", data)
    except (OSError, socket.error) as exc:
        print("[tcp] error: {}".format(exc))
        state.close_tcp()


def send_udp(state, message):
    # type: (ClientState, str) -> None
    payload = message.encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silence_udp_connreset(sock)
    sock.settimeout(state.timeout)
    try:
        sock.sendto(payload, (state.host, state.port))
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            print("[udp] (no reply within {}s)".format(state.timeout))
            return
        except ConnectionResetError:
            print("[udp] connection reset (ICMP unreachable?)")
            return
        print_reply("udp", data, addr)
    except OSError as exc:
        print("[udp] error: {}".format(exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


def print_reply(proto, data, addr=None):
    # type: (str, bytes, Optional[Tuple]) -> None
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)
    text = text.strip()
    if addr is not None:
        print("[{}] from {}:{} {}".format(proto, addr[0], addr[1], text))
    else:
        print("[{}] {}".format(proto, text))


def split_host_port(value, default_host, default_port):
    # type: (str, str, int) -> Tuple[str, int]
    value = (value or "").strip()
    if not value:
        return default_host, default_port
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("invalid address: {}".format(value))
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if value.startswith(":"):
        return default_host, int(value[1:])
    if value.isdigit():
        return default_host, int(value)
    if value.count(":") == 1:
        host, _, port_s = value.partition(":")
        return (host or default_host), (int(port_s) if port_s else default_port)
    return value, default_port


def handle_line(state, line):
    # type: (ClientState, str) -> bool
    """
    Process one input line.
    Returns False when the client should exit.
    """
    line = line.strip()
    if not line:
        return True

    lower = line.lower()
    if lower in ("q", "quit", "exit"):
        return False
    if lower in ("h", "help", "?"):
        print(HELP_TEXT)
        return True

    # verb + rest
    parts = line.split(None, 1)
    verb = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""

    if verb in ("t", "tcp"):
        if rest == "":
            print("[tcp] usage: t <message>")
            return True
        send_tcp(state, rest)
        return True

    if verb in ("u", "udp"):
        if rest == "":
            print("[udp] usage: u <message>")
            return True
        send_udp(state, rest)
        return True

    if verb == "host":
        if not rest:
            print("host = {}".format(state.host))
            return True
        state.close_tcp()
        state.host = rest.strip()
        print("host -> {}".format(state.host))
        return True

    if verb == "port":
        if not rest:
            print("port = {}".format(state.port))
            return True
        try:
            state.port = int(rest.strip())
        except ValueError:
            print("invalid port: {!r}".format(rest))
            return True
        state.close_tcp()
        print("port -> {}".format(state.port))
        return True

    if verb == "target":
        if not rest:
            print("target = {}".format(state.target))
            return True
        try:
            host, port = split_host_port(rest.strip(), state.host, state.port)
        except ValueError as exc:
            print(str(exc))
            return True
        state.close_tcp()
        state.host = host
        state.port = port
        print("target -> {}".format(state.target))
        return True

    if verb == "timeout":
        if not rest:
            print("timeout = {}".format(state.timeout))
            return True
        try:
            state.timeout = float(rest.strip())
        except ValueError:
            print("invalid timeout: {!r}".format(rest))
            return True
        print("timeout -> {}".format(state.timeout))
        return True

    # bare message → TCP
    send_tcp(state, line)
    return True


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Interactive TCP/UDP echo test client")
    p.add_argument(
        "-t",
        "--target",
        default="{}:{}".format(DEFAULT_HOST, DEFAULT_PORT),
        help="server host:port (default: %(default)s)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="recv timeout seconds (default: %(default)s)",
    )
    p.add_argument(
        "-c",
        "--command",
        action="append",
        default=[],
        help="run one command non-interactively (repeatable), then exit",
    )
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    try:
        host, port = split_host_port(args.target, DEFAULT_HOST, DEFAULT_PORT)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)

    state = ClientState(host, port, args.timeout)

    # non-interactive batch mode
    if args.command:
        for cmd in args.command:
            if not handle_line(state, cmd):
                break
        state.close_tcp()
        return

    print("======================================")
    print(" Echo test client")
    print(" target {}".format(state.target))
    print(" type 'help' for commands")
    print("======================================")

    try:
        while True:
            try:
                line = input("{}> ".format(state.target))
            except EOFError:
                print()
                break
            if not handle_line(state, line):
                break
    except KeyboardInterrupt:
        print()
    finally:
        state.close_tcp()
        print("bye")


if __name__ == "__main__":
    main()
