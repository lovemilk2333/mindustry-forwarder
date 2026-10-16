#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Echo test server — listen TCP + UDP on the same port.

Reply format (UTF-8 text):
    TCP <ip>:<port> <content>
    UDP <ip>:<port> <content>

Default port 6568 (decoder side). Use this as a stand-in for Mindustry
when testing encoder/decoder without a real game server.

Python 3.8+ / stdlib only.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from typing import Tuple

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 6567
BUFFER_SIZE = 65535
BACKLOG = 128


def peer_str(addr: Tuple) -> str:
    host = addr[0]
    port = int(addr[1])
    # collapse IPv4-mapped IPv6
    if host.startswith("::ffff:"):
        host = host[7:]
    return "{}:{}".format(host, port)


def make_reply(proto: str, addr: Tuple, data: bytes) -> bytes:
    try:
        content = data.decode("utf-8", errors="replace")
    except Exception:
        content = repr(data)
    # one logical line; no leading/trailing whitespace on content
    content = content.strip()
    line = "{} {} {}\n".format(proto, peer_str(addr), content)
    return line.encode("utf-8")


def silence_udp_connreset(sock: socket.socket) -> None:
    sio = getattr(socket, "SIO_UDP_CONNRESET", None)
    if sio is None:
        return
    try:
        sock.ioctl(sio, False)
    except (AttributeError, OSError, TypeError, ValueError):
        pass


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


def handle_tcp(conn: socket.socket, addr: Tuple) -> None:
    print("[TCP] connection from {}".format(peer_str(addr)))
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            reply = make_reply("TCP", addr, data)
            print("[TCP] {} -> {!r}".format(peer_str(addr), data[:200]))
            try:
                conn.sendall(reply)
            except OSError as exc:
                print("[TCP] send error {}: {}".format(peer_str(addr), exc))
                break
    except OSError as exc:
        print("[TCP] error {}: {}".format(peer_str(addr), exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass
        print("[TCP] closed {}".format(peer_str(addr)))


def tcp_server(host: str, port: int) -> None:
    # Dual-stack when host is 0.0.0.0 / :: — prefer IPv4 bind for simplicity
    # matching the forwarder defaults.
    family = socket.AF_INET6 if ":" in host and not host.startswith("::ffff:") else socket.AF_INET
    if host in ("0.0.0.0", "", "::"):
        family = socket.AF_INET
        host = host or "0.0.0.0"

    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(BACKLOG)
        print("[TCP] listening on {}:{}".format(host, port))
        while True:
            try:
                conn, addr = srv.accept()
            except OSError as exc:
                print("[TCP] accept error:", exc)
                continue
            t = threading.Thread(target=handle_tcp, args=(conn, addr), daemon=True)
            t.start()
    finally:
        try:
            srv.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------


def udp_server(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host and not host.startswith("::ffff:") else socket.AF_INET
    if host in ("0.0.0.0", "", "::"):
        family = socket.AF_INET
        host = host or "0.0.0.0"

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    silence_udp_connreset(sock)
    try:
        sock.bind((host, port))
        print("[UDP] listening on {}:{}".format(host, port))
        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
            except ConnectionResetError:
                # Windows ICMP port-unreachable
                continue
            except OSError as exc:
                print("[UDP] recvfrom error:", exc)
                continue
            if not data:
                continue
            reply = make_reply("UDP", addr, data)
            print("[UDP] {} -> {!r}".format(peer_str(addr), data[:200]))
            try:
                sock.sendto(reply, addr)
            except OSError as exc:
                print("[UDP] sendto error {}: {}".format(peer_str(addr), exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="TCP+UDP echo test server")
    p.add_argument(
        "-l",
        "--listen",
        default="{}:{}".format(DEFAULT_HOST, DEFAULT_PORT),
        help="listen host:port (default: %(default)s)",
    )
    return p.parse_args(argv)


def split_host_port(value: str, default_host: str, default_port: int):
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


def main(argv=None) -> None:
    args = parse_args(argv)
    host, port = split_host_port(args.listen, DEFAULT_HOST, DEFAULT_PORT)

    print("======================================")
    print(" Echo test server (TCP + UDP)")
    print(" listen {}:{}".format(host, port))
    print(" reply: <PROTO> <ip>:<port> <content>")
    print("======================================")

    tcp_t = threading.Thread(target=tcp_server, args=(host, port), daemon=True)
    udp_t = threading.Thread(target=udp_server, args=(host, port), daemon=True)
    tcp_t.start()
    udp_t.start()

    try:
        tcp_t.join()
        udp_t.join()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
