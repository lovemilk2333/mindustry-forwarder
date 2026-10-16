# Mindustry Forwarder

TCP/UDP tunnel that forwards Mindustry client traffic through a constrained
path (for example a Windows host that can only reach a Linux “stick”), while
optionally preserving the **real client source IP** on the game server via
Linux `IP_TRANSPARENT`.

```
  Game clients                    Windows / edge                     Linux (game host)
 ┌────────────┐   TCP+UDP 6567   ┌─────────────────┐  TCP tunnel   ┌──────────────────┐
 │  Mindustry │ ───────────────► │ encoder_server  │ ────────────► │ decoder (Go)     │
 │  clients   │                  │ (Python 3.8+)   │   :6568       │   :6568          │
 └────────────┘                  └─────────────────┘               │        │         │
                                                                   │  plain or        │
                                                                   │  IP_TRANSPARENT  │
                                                                   │        ▼         │
                                                                   │ Mindustry :6567  │
                                                                   └──────────────────┘
```

| Component | Language | Role |
|-----------|----------|------|
| **Encoder** | Python 3.8+ (stdlib only) | Listens like a Mindustry server (`TCP+UDP :6567`), opens one TCP tunnel per client session to the decoder, prepends a context header with the real client address |
| **Decoder** | Go | Accepts tunnels, dials the real Mindustry (or echo) server, optionally spoofs the client source IP |

Windows-friendly encoder: no third-party packages, async I/O, and
`SIO_UDP_CONNRESET` handling so ICMP port-unreachable does not kill UDP sessions.

---

## Protocol

Every tunnel starts with a **context header** (big-endian), then payload.

| Field | Size | Notes |
|-------|------|--------|
| `flags` | 1 byte | bit0 = TCP (`IS_TCP`), bit7 = IPv6 (`IS_IPV6`) |
| `port` | 2 bytes | client source port (uint16 BE) |
| `address` | 4 or 16 bytes | IPv4 or IPv6 |

After the header:

- **TCP session** — raw byte stream (no framing).
- **UDP session** — repeated frames: `uint16 BE length` + payload  
  (preserves datagram boundaries over TCP).

Encoder and decoder must stay in sync on this layout
(`encoder/encoder_server.py` ↔ `decoder/cmd/decoder_server.go`).

---

## Build (decoder)

Requires Go. ARM64 cross-build uses [Zig](https://ziglang.org/) as a
glibc-2.31-targeting C toolchain (path: `$HOME/tools/zig/zig`).

```bash
make                  # both amd64 and arm64
make decoder-amd64    # bin/decoder/amd64/mindustry-forwarder-decoder
make decoder-arm64    # bin/decoder/arm64/mindustry-forwarder-decoder
make DEBUG=1 decoder-amd64
make clean
```

| Artifact | Notes |
|----------|--------|
| `bin/decoder/amd64/...` | `CGO_ENABLED=0`, static |
| `bin/decoder/arm64/...` | Zig `aarch64-linux-gnu.2.31`, dynamic glibc |

The encoder is plain Python — no build step.

```bash
python3 encoder/encoder_server.py --help
```

---

## Run

### 1. Mindustry (or echo) on the Linux host

```bash
# real game server on 6567, or for plumbing tests:
python3 tests/server.py -l 0.0.0.0:6567
```

### 2. Decoder (Linux, **root** recommended)

Default backend is `127.0.0.1:6567`. Spoofing a foreign source toward
`127.0.0.0/8` cannot complete a TCP handshake, so when the backend is loopback
the decoder **automatically**:

1. Extracts an embedded setup script to a temp file, runs it, deletes it  
2. Adds lo alias `172.31.255.1/32` and sysctls (`route_localnet`, `rp_filter=0`, …)  
3. Rewrites the backend to `172.31.255.1:6567` and enables transparent mode  
4. Per session: `ip route replace local <clientIP>/32 dev lo` so SYN-ACK/UDP
   replies to the spoofed source stay on this host  
5. On exit (SIGINT/SIGTERM): removes client local routes and the lo alias  

```bash
sudo ./mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `-l / --listen` | Tunnel listen address (default `:6568`) |
| `-m / --mindustry` | Game server `host:port` (default `127.0.0.1:6567`) |
| `-p / --mindustry-port` | Shorthand: `127.0.0.1:<port>` |
| `--timeout` | Connect / header timeout (default `5s`) |
| `--setup-lo-ip` | Lo alias IP (default `172.31.255.1`) |
| `--no-auto-setup-lo` | Do not rewrite 127/8 backends |
| `--no-transparent` | Never spoof client IP (plain dial only) |

If Mindustry already listens on a **non-loopback** address, point `-m` there
directly (no lo rewrite needed):

```bash
sudo ./mindustry-forwarder-decoder -l :6568 -m 192.168.1.10:6567
```

Transparent dial needs `CAP_NET_ADMIN` (typically root), `iproute2`, and a
working `ip` binary.

### 3. Encoder (Windows or any client-side host)

```bash
python encoder_server.py -l 0.0.0.0:6567 -s <decoder-host>:6568
```

| Flag | Meaning |
|------|---------|
| `-l / --listen` | Local listen for game clients (default `0.0.0.0:6567`) |
| `-s / --server` | Decoder host:port (default `10.22.33.1:6568`) |
| `-t / --timeout` | Connect timeout seconds |
| `--udp-idle` | Drop idle UDP sessions after N seconds (default `60`) |
| `--tcp-only` / `--udp-only` | Single protocol |
| `-v` | Debug logging |

Point Mindustry clients at the encoder host (`<encoder-ip>:6567`).

### systemd (optional)

A sample unit is provided at
`decoder/mindustry-forwarder-decoder.service`. Adjust paths and
`User=`/`CapabilityBoundingSet=` as needed; transparent mode generally
requires root or ambient `CAP_NET_ADMIN`.

---

## Testing without Mindustry

```bash
# Linux: echo server pretending to be Mindustry
python3 tests/server.py -l 0.0.0.0:6567

# Linux: decoder (root for transparent)
sudo ./mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567

# Client host: encoder
python3 encoder/encoder_server.py -l 0.0.0.0:6567 -s <decoder-ip>:6568

# Interactive client (default target 127.0.0.1:6567 = encoder)
python3 tests/client.py -t 127.0.0.1:6567
```

Client commands:

| Input | Action |
|-------|--------|
| `t <msg>` / `tcp <msg>` | Send over TCP |
| `u <msg>` / `udp <msg>` | Send over UDP |
| bare line | Same as TCP |
| `host` / `port` / `target` | Change destination |
| `help` / `quit` | Help / exit |

Batch mode:

```bash
python3 tests/client.py -t 127.0.0.1:6567 -c 't hello' -c 'u hello'
```

Echo reply format:

```text
TCP <ip>:<port> <content>
UDP <ip>:<port> <content>
```

With transparent mode working, `<ip>` should be the **real client address**
from the encoder context (not the decoder’s lo alias).

---

## Transparent proxy notes

| Backend | Transparent? | What you see on the game server |
|---------|--------------|----------------------------------|
| `127.0.0.1:6567` without auto setup | Off (forced plain) | Local source IP |
| `127.0.0.1:6567` with auto setup (default) | On via `172.31.255.1` + per-client local routes | Real client IP |
| Non-loopback LAN IP | On (if permitted) | Real client IP |
| `--no-transparent` | Always off | Local source IP |

Do **not** try to rewrite TCP/UDP headers in userspace to fake the source
address. Sequence numbers, ACKs, retransmits, and checksums make that a full
stack rewrite. The supported path is kernel `IP_TRANSPARENT` plus local
routes on `lo` when the host has no other NIC.

If transparent dial fails, the decoder logs the error and **retries plain**
so the session still works (source IP will then be wrong).

---

## Layout

```text
.
├── Makefile
├── README.md
├── decoder/
│   ├── cmd/
│   │   ├── decoder_server.go          # main
│   │   └── setup-lo-transparent.sh    # embedded via //go:embed
│   ├── go.mod
│   └── mindustry-forwarder-decoder.service
├── encoder/
│   └── encoder_server.py
└── tests/
    ├── client.py                      # interactive TCP/UDP client
    └── server.py                      # TCP+UDP echo server
```

---

## Requirements

| Side | Needs |
|------|--------|
| Encoder | Python 3.8+ (3.8–3.x), Windows or Linux, stdlib only |
| Decoder | Linux, root (or `CAP_NET_ADMIN`) for transparent mode, `bash`, `ip` |
| Build | Go toolchain; Zig at `$HOME/tools/zig/zig` for arm64 |

---

## License / status

Internal tooling for wifi-stick / lab use. No warranty.
