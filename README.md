# Mindustry Forwarder

TCP/UDP tunnel for Mindustry. Clients talk to a Python **encoder** (edge /
Windows). The encoder opens one TCP tunnel per session to a Go **decoder**
(Linux game host). The decoder dials the real Mindustry server and can
preserve the **real client source IP** with Linux `IP_TRANSPARENT`.

```
  Game clients                 Edge host                         Linux game host
 ┌────────────┐  TCP+UDP :6567 ┌──────────────────┐  TCP :6568  ┌─────────────────────────┐
 │  Mindustry │ ─────────────► │ encoder_server.py│ ──────────► │ mindustry-forwarder-    │
 │  clients   │                │ (Python 3.8+,    │  + context  │ decoder (Go)            │
 └────────────┘                │  stdlib only)    │  header     │                         │
                               └──────────────────┘             │  plain or IP_TRANSPARENT│
                                                                │            │            │
                                                                │            ▼            │
                                                                │   Mindustry :6567       │
                                                                └─────────────────────────┘
```

| Component | Path | Role |
|-----------|------|------|
| **Encoder** | `encoder/encoder_server.py` | Listen like Mindustry (`TCP+UDP :6567`). One TCP tunnel per client session to the decoder; first bytes = context header (real client IP/port/proto). |
| **Decoder** | `decoder/cmd/decoder_server.go` | Accept tunnels, parse context, dial Mindustry. Optional source spoof via `IP_TRANSPARENT` + per-client `lo` local routes. |
| **Tests** | `tests/server.py`, `tests/client.py` | TCP+UDP echo stand-in and interactive client. |

Logging prefixes:

- Encoder: `[Mindustry Forwarder Client] UTC::…`
- Decoder: `[Mindustry Forwarder Server] UTC::…`
- Session tags: `[TCP 1.2.3.4:5678]` / `[UDP 1.2.3.4:5678]`

---

## Wire protocol

All multi-byte integers are **big-endian**. Encoder and decoder must match
(`encoder/encoder_server.py` ↔ `decoder/cmd/decoder_server.go`).

### Context header (once per tunnel)

Sent as the first bytes on the decoder-bound TCP connection.

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | `flags` | 1 | bit0 = `IS_TCP` (1), bit7 = `IS_IPV6` (128) |
| 1 | `port` | 2 | Client source port (`uint16`) |
| 3 | `address` | 4 or 16 | IPv4 (`ip.packed` / 4 bytes) or IPv6 (16 bytes) |

| `flags` | Address family | Protocol | Total header length |
|---------|----------------|----------|---------------------|
| `0x00` | IPv4 | UDP | 7 |
| `0x01` | IPv4 | TCP | 7 |
| `0x80` | IPv6 | UDP | 19 |
| `0x81` | IPv6 | TCP | 19 |

Constants (both sides):

```text
IS_TCP_MASK  = 1
IS_IPV6_MASK = 128
```

IPv4-mapped IPv6 peers (`:ffff:x.x.x.x`) are collapsed to plain IPv4 before packing.

### Payload after the header

| Session | Framing |
|---------|---------|
| **TCP** (`IS_TCP`) | Raw byte stream. No extra framing. Bidirectional `io.Copy` / asyncio pipe. |
| **UDP** (no `IS_TCP`) | Length-prefixed datagrams on the TCP tunnel: `uint16 BE length` + `payload` (0…65535 bytes). One frame ↔ one UDP datagram toward Mindustry / the client. |

```text
UDP frame:  [ len_hi ][ len_lo ][ payload … ]
```

Decoder: each frame body → one `Write` on the backend UDP socket.  
Encoder: each TCP-read frame → one `sendto` to the original client `(ip, port)`.

---

## Repository layout

```text
.
├── Makefile                              # decoder build entry
├── README.md
├── LICENSE                               # BSD 3-Clause
├── .gitignore                            # bin/, build/, .venv/, …
│
├── decoder/                              # Go module (server side)
│   ├── go.mod / go.sum
│   ├── mindustry-forwarder-decoder.service
│   └── cmd/
│       ├── decoder_server.go             # main + //go:embed
│       └── setup-lo-transparent.sh       # embedded lo setup (extracted at runtime)
│
├── encoder/                              # Python client side (no build)
│   └── encoder_server.py
│
├── tests/
│   ├── server.py                         # TCP+UDP echo (default :6567)
│   └── client.py                         # interactive / batch client
│
└── bin/decoder/                          # build output (gitignored)
    ├── amd64/mindustry-forwarder-decoder
    └── arm64/mindustry-forwarder-decoder
```

---

## Build (decoder only)

Firstly, setup Zig with aarch64-linux-gnu.2.31 for Linux 5.15
```bash
mkdir -p "$HOME/tools"
curl -sL -o /tmp/zig.tar.xz \
    https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz
tar -C "$HOME/tools" -xf /tmp/zig.tar.xz
mv "$HOME/tools/zig-x86_64-linux-0.14.1" "$HOME/tools/zig"
```

---

```bash
make                  # amd64 + arm64
make decoder-amd64    # → bin/decoder/amd64/mindustry-forwarder-decoder
make decoder-arm64-5.15    # → bin/decoder/arm64-5.15/mindustry-forwarder-decoder
make decoder          # both
make DEBUG=1 decoder-amd64
make clean            # rm -rf bin
make help
```

| Target | Output | Linkage |
|--------|--------|---------|
| `decoder-amd64` | `bin/decoder/amd64/mindustry-forwarder-decoder` | `CGO_ENABLED=0`, static Linux amd64 |
| `decoder-arm64-5.15` | `bin/decoder/arm64-5.15/mindustry-forwarder-decoder` | Zig `aarch64-linux-gnu.2.31`, `CGO_ENABLED=1`, `-linkmode external` |

- Build the whole package `./cmd` so `//go:embed setup-lo-transparent.sh` is included.
- ARM64 needs Zig at `$HOME/tools/zig/zig` (override with `ZIG=…` only if you edit the Makefile).
- Release builds use `-trimpath -ldflags "-s -w"` plus `CommitHash` / `BuildTime`.

Encoder needs no compile step:

```bash
python3 encoder/encoder_server.py --help
```

---

## Run

### Ports (defaults)

| Role | Default |
|------|---------|
| Mindustry / echo | TCP+UDP **6567** |
| Decoder tunnel listen | TCP **6568** |
| Encoder → decoder | TCP to decoder host **:6568** |
| Encoder client listen | TCP+UDP **6567** |

### 1. Game server (or echo) on Linux

```bash
# real Mindustry on 6567, or:
python3 tests/server.py -l 0.0.0.0:6567
```

Bind `0.0.0.0` (or the lo alias) so transparent dials to `172.31.255.1:6567` are accepted.

### 2. Decoder (Linux)

```bash
sudo bin/decoder/amd64/mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567
# or after install:
sudo mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567
```

#### CLI

| Flag | Default | Meaning |
|------|---------|---------|
| `-l`, `--listen` | `:6568` | Tunnel listen `host:port` |
| `-m`, `--mindustry` | `127.0.0.1:6567` | Backend game server (`host:port`; bare `:port` or `port` → `127.0.0.1:port`) |
| `--timeout` | `5s` | Context read + dial timeout |
| `--setup-lo-ip` | `172.31.255.1` | Lo alias when auto-setup runs |
| `--no-auto-setup-lo` | off | Do not rewrite 127/8 backends |
| `--no-transparent` | off | Never use `IP_TRANSPARENT` |

#### Auto lo setup (127/8 backends)

Spoofing a foreign source toward `127.0.0.0/8` cannot finish TCP handshake
(dial `i/o timeout`). If `-m` is loopback, transparent is desired, and
`--no-auto-setup-lo` is not set, the decoder:

1. Writes the embedded `setup-lo-transparent.sh` under a temp dir, runs it, **deletes** the temp tree  
2. Adds `172.31.255.1/32` on `lo` and sysctls (`route_localnet`, `rp_filter=0`, `accept_local=1`, `ip_forward=1`)  
3. Rewrites backend to `172.31.255.1:<port>` so transparent dial is allowed  
4. **Per session**: `ip route replace local <clientIP>/32 dev lo` (refcounted) so SYN-ACK / UDP replies to the spoofed source stay on this host  
5. On **SIGINT / SIGTERM / exit**: drop client local routes, run setup undo, remove lo alias  

Needs **root** (or `CAP_NET_ADMIN`), `bash` (via `/usr/bin/env`), and `ip` (iproute2).

Non-loopback backend (no rewrite):

```bash
sudo mindustry-forwarder-decoder -l :6568 -m 192.168.1.10:6567
```

Plain only (no spoof, no auto lo):

```bash
mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567 --no-transparent
# or
mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567 --no-auto-setup-lo
```

If transparent dial fails, the decoder logs the error, releases the local route,
and **retries plain** so the session still works (source IP will be local).

### 3. Encoder (Windows or Linux edge)

```bash
python encoder_server.py -l 0.0.0.0:6567 -s <decoder-host>:6568
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-l`, `--listen` | `0.0.0.0:6567` | Client-facing TCP+UDP listen |
| `-s`, `--server` | `10.22.33.1:6568` | Decoder tunnel address |
| `-t`, `--timeout` | `5` | Connect timeout (seconds) |
| `--udp-idle` | `60` | Idle UDP session timeout (seconds) |
| `--backlog` | `128` | TCP listen backlog |
| `--tcp-only` / `--udp-only` | off | Single protocol |
| `-v`, `--verbose` | off | Debug logging |

Windows notes baked into the encoder:

- `SIO_UDP_CONNRESET` disabled so ICMP port-unreachable does not abort UDP  
- Connection aborts (`WinError 1236` / reset) are treated as normal pipe end  

Point Mindustry clients at `<encoder-host>:6567`.

### systemd

Sample unit: `decoder/mindustry-forwarder-decoder.service`

```ini
[Unit]
Description=mindustry-forwarder-decoder

[Service]
Type=simple
ExecStart=/usr/local/bin/mindustry-forwarder-decoder
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Install the binary under `/usr/local/bin/`, adjust `ExecStart` flags (`-l`, `-m`, …).
Transparent mode generally needs root or ambient `CAP_NET_ADMIN`.

---

## Testing without Mindustry

```bash
# Linux host
python3 tests/server.py -l 0.0.0.0:6567
sudo bin/decoder/amd64/mindustry-forwarder-decoder -l :6568 -m 127.0.0.1:6567

# Edge host
python3 encoder/encoder_server.py -l 0.0.0.0:6567 -s <decoder-ip>:6568

# Against encoder (default) or echo/decoder directly
python3 tests/client.py -t 127.0.0.1:6567
python3 tests/client.py -t 127.0.0.1:6567 -c 't hello' -c 'u hello'
```

### `tests/server.py`

- Listens **TCP + UDP** on the same port (default `0.0.0.0:6567`)  
- Reply (UTF-8, one line): `TCP <ip>:<port> <content>` / `UDP <ip>:<port> <content>`  
- Content is stripped of surrounding whitespace  

With transparent mode working, `<ip>` is the **real client** from the context
header (e.g. `10.0.192.101`), not `172.31.255.1`.

### `tests/client.py`

| Input | Action |
|-------|--------|
| `t <msg>` / `tcp <msg>` | Send via TCP (connection reused until drop) |
| `u <msg>` / `udp <msg>` | Send via UDP |
| bare line | Same as TCP |
| `host` / `port` / `target` | Change destination |
| `timeout <sec>` | Recv timeout |
| `help` / `quit` | Help / exit |

| Flag | Default |
|------|---------|
| `-t`, `--target` | `127.0.0.1:6567` |
| `--timeout` | `3` |
| `-c`, `--command` | repeatable; batch then exit |

---

## Transparent proxy matrix

| Backend | Auto lo | Transparent dial | Source IP on game server |
|---------|---------|------------------|---------------------------|
| `127.0.0.1:6567` (default) | yes | yes → `172.31.255.1:6567` + client local routes | Real client IP |
| `127.0.0.1:6567` + `--no-auto-setup-lo` | no | forced **plain** (127/8) | Decoder local IP |
| Non-loopback LAN IP | n/a | yes (if permitted) | Real client IP |
| `--no-transparent` | skipped | always plain | Decoder local IP |

Do **not** rewrite TCP/UDP headers in userspace to fake the source address.
That requires owning sequence numbers, ACKs, retransmits, and checksums (a
full stack). The supported path is kernel `IP_TRANSPARENT` plus
`ip route local <client>/32 dev lo` when the host is lo-only.

---

## Session model

| Path | Encoder | Decoder |
|------|---------|---------|
| TCP | One tunnel TCP connection per accepted client TCP | Parse context → dial backend TCP (optionally spoofed) → bidirectional copy |
| UDP | One tunnel TCP connection per client `(ip, port)`; idle reap | Parse context → dial backend UDP → length-prefixed frames both ways |

UDP idle sessions are closed after `--udp-idle` seconds without traffic.
Decoder clears header read deadline after the context is parsed so long game
sessions are not cut by the initial timeout.

---

## Requirements

| Side | Needs |
|------|--------|
| **Encoder** | Python **3.8+**, Windows x64 or Linux, **stdlib only** (asyncio, socket, struct, …) |
| **Decoder runtime** | Linux; root / `CAP_NET_ADMIN` for transparent; `bash`; `ip` (iproute2) |
| **Decoder build** | Go toolchain; for arm64: Zig at `$HOME/tools/zig/zig` targeting `aarch64-linux-gnu.2.31` |
| **Tests** | Same Python as encoder |

---

## License

BSD 3-Clause. See [LICENSE](LICENSE).
