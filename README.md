# socks-proxy

A high-performance, event-driven SOCKS5 proxy server written in a single C file. Fully RFC 1928/1929 compliant, supporting all three SOCKS5 commands (CONNECT, BIND, UDP ASSOCIATE), multiple authentication methods, and cross-platform operation on macOS, Linux, and Windows.

**Version:** 0.2.0  
**License:** PolyForm Noncommercial 1.0.0

---

## Features

### Protocol Compliance
- **RFC 1928** — SOCKS Protocol Version 5
- **RFC 1929** — Username/Password authentication
- **RFC 1961** — GSSAPI authentication (optional, compile-time flag)

### SOCKS5 Commands
| Command | Description |
|---|---|
| `CONNECT` | TCP proxying to a remote host |
| `BIND` | Two-stage reverse connection (e.g. active-mode FTP) |
| `UDP ASSOCIATE` | UDP relay with full SOCKS5 header encapsulation |

### Address Types
- IPv4
- IPv6
- Domain name (resolved server-side)

### Authentication Methods
- **No Auth** — open proxy mode
- **Username/Password** (RFC 1929) — constant-time credential comparison to prevent timing attacks
- **GSSAPI** (RFC 1961) — Kerberos/GSS, opt-in at compile time via `GSSAPI=1`

### Performance
- **Single-threaded event loop** — no thread-per-connection overhead
- **kqueue** on macOS/BSD, **epoll** on Linux (edge-triggered)
- **Non-blocking async connect** — outbound connections never stall the loop
- **64 KB shared relay buffer** — zero per-connection allocation during relay
- **256 KB socket send/recv buffers** — enlarged for throughput
- **`TCP_NODELAY`** — disabled Nagle algorithm on all sockets
- **`SO_REUSEPORT`** — available where the OS supports it
- **`accept4()`** on Linux — atomic `O_NONBLOCK` on accept
- **Deferred connection cleanup** — avoids use-after-free within event batches
- **~200 byte active connection struct** — compact memory footprint
- **~5 MB base RSS** — minimal baseline memory usage
- **1,000,000 default max connections** — fd limit auto-raised at startup

### Security
- **Connection limiting** — `--max-conn` drops excess connections
- **IP allowlist** — `--allow-ip` accepts connections only from listed IPs (binary-searched, repeatable)
- **Constant-time credential comparison** — guards against timing side-channels on auth

### Observability
- **Timestamped log lines** — `[YYYY-MM-DD HH:MM:SS]` prefix on every message
- **Per-session statistics** — bytes sent, bytes received, and duration logged on close
- **Debug mode** — `-d` / `--debug` enables verbose protocol-level tracing
- **Log levels** — INFO, WARN, ERROR, DEBUG

### Deployment
- **`--install`** — installs the binary and generates a systemd unit file
- **`--uninstall`** — removes the installed binary and unit file
- **`--version`** / **`-V`** — prints the version string and exits

---

## Building

Requires a C11 compiler (clang or gcc). The `Makefile` auto-detects the available compiler.

```sh
# Build the proxy binary
make

# Build the test suite
make tests

# Build and run the full test suite
make check

# Build with GSSAPI support enabled (requires libgssapi_krb5 on Linux or GSS.framework on macOS)
make GSSAPI=1

# Clean build artifacts
make clean
```

The binary is built as `./socks5`.

---

## Usage

```
Usage: socks5 [options] [port]

Options:
  -p, --port <port>        Port to listen on (default: 1080)
  -b, --bind <ip>          Bind address (default: 0.0.0.0)
  -u, --user <user:pass>   Add user (enables auth). Repeatable.
  --max-conn <n>           Max concurrent connections (default: 1000000)
  --allow-ip <ip>          Allow only specific IP. Repeatable.
  -d, --debug              Enable verbose debug logging
  --install <mode>         Install as service (systemd) or to path
  --uninstall <mode>       Uninstall service (systemd) or from path
  -V, --version            Print version and exit
  -h, --help               Show this help message
```

### Examples

**Open proxy on the default port (1080):**
```sh
./socks5
```

**Specify a custom port:**
```sh
./socks5 --port 8080
# or
./socks5 8080
```

**Require username/password authentication:**
```sh
./socks5 --port 1080 --user alice:s3cr3t --user bob:hunter2
```
Adding any `--user` automatically enables the `USERNAME/PASSWORD` auth method and rejects unauthenticated clients.

**Bind to a specific interface:**
```sh
./socks5 --port 1080 --bind 192.168.1.10
```

**Restrict access to specific client IPs:**
```sh
./socks5 --port 1080 --allow-ip 10.0.0.1 --allow-ip 10.0.0.2
```
When any `--allow-ip` is set, all other source IPs are rejected immediately at accept time.

**Cap concurrent connections:**
```sh
./socks5 --port 1080 --max-conn 5000
```

**Enable debug logging:**
```sh
./socks5 --port 1080 --debug
```

**Full example — auth + restricted bind + capped connections:**
```sh
./socks5 --port 1080 --bind 0.0.0.0 \
         --user deploy:p@ssw0rd \
         --allow-ip 10.10.0.0 \
         --max-conn 10000
```

### Verify connectivity with curl

```sh
curl --socks5-hostname localhost:1080 https://example.com
```

With authentication:
```sh
curl --socks5-hostname alice:s3cr3t@localhost:1080 https://example.com
```

---

## Systemd Deployment

Install the binary to `/usr/local/bin` and write a systemd unit file:

```sh
sudo ./socks5 --install systemd
sudo systemctl enable --now socks5
```

The generated unit runs `socks5 --port 1080 --max-conn 1000000` by default. Edit `/etc/systemd/system/socks5.service` to customise arguments, then reload:

```sh
sudo systemctl daemon-reload
sudo systemctl restart socks5
```

To remove the installation:

```sh
sudo ./socks5 --uninstall systemd
```

---

## Architecture

### Event Loop

The server uses a single-threaded event loop backed by the native OS multiplexer:

| Platform | Backend | Trigger mode |
|---|---|---|
| macOS / FreeBSD / OpenBSD / NetBSD | `kqueue` | `EV_CLEAR` (edge-triggered) |
| Linux | `epoll` | `EPOLLET` (edge-triggered) |

Up to 512 events are processed per `kevent` / `epoll_wait` call. After each batch, deferred-dead connections (up to 512) are freed to prevent use-after-free bugs from same-batch cascades.

### Connection State Machine

Each connection progresses through a sequence of phases:

```
GREETING_READ → GREETING_WRITE
  ↓ (no auth)          ↓ (user/pass)     ↓ (GSSAPI)
REQUEST_READ       AUTH_READ          GSSAPI_READ
                   AUTH_WRITE         GSSAPI_WRITE
                       ↓                   ↓
                   REQUEST_READ ←─────────┘
                       ↓
           ┌─── CONNECT ───┬─── BIND ────┬─── UDP ASSOCIATE ───┐
      CONNECTING      BIND_LISTEN      PHASE_UDP              ...
      REPLY_WRITE     BIND_REPLY2
           └────────────────┴────────────────→ RELAY → CLOSING
```

All I/O is non-blocking. The handshake accumulates bytes incrementally across multiple read events — fragmented packets are handled correctly at every phase.

### Relay Engine

Once both sides are connected, `relay_data()` pumps data between client and remote using a single 64 KB static buffer. If a `send()` would block, the unsent remainder is heap-allocated into a per-connection overflow buffer and the destination fd is armed for `EPOLLOUT` / `EVFILT_WRITE`. The overflow is drained on the next writable event before more reads are attempted.

### UDP Relay

For `UDP ASSOCIATE`, a UDP socket is bound on an ephemeral port and registered with the event loop. Packets from the client carry a SOCKS5 UDP header encoding the target address; the relay strips the header and forwards the payload. Packets arriving from the remote are re-wrapped with a header and delivered to the client. The TCP control channel is monitored in parallel; closing it tears down the UDP relay.

---

## Testing

The test suite is a standalone C program (`tests.c`) that forks the `socks5` binary and exercises it over real sockets.

```sh
make check
```

### Test coverage

| Test | Description |
|---|---|
| Basic No Auth | Server selects `NO AUTH` (0x00) when no users are configured |
| Auth Success | Server selects `USERNAME/PASSWORD` (0x02) and accepts valid credentials |
| Auth Fail | Server closes the connection on wrong password (errno `EACCES`) |
| Auth Enforced | Server returns `0xFF` (no acceptable methods) when client offers only `NO AUTH` but auth is required |
| Auth Fragmented | Handshake and RFC 1929 auth bytes delivered one-at-a-time; full reassembly verified |
| CONNECT Fragmented | SOCKS5 CONNECT request delivered byte-by-byte; server still produces a valid reply |
| Version Flag | `--version` exits 0 and prints a version string containing a dot |
| Observability | Log output after a session contains `Session finished:` with a timestamp |
| Security Max Conn | `--max-conn 1` causes the second client to be rejected |
| Security Allow IP | `--allow-ip 1.2.3.4` blocks loopback; `--allow-ip 127.0.0.1` permits it |
| BIND Command | Full two-reply BIND flow with relay data verification |
| UDP ASSOCIATE | Full UDP relay round-trip including header encapsulation and response unwrapping |
| GSSAPI Advertised | Server selects GSSAPI (0x01) when built with `GSSAPI=1` and client offers it |

---

## GSSAPI / Kerberos

GSSAPI support is disabled by default to avoid adding a mandatory dependency. Compile it in with:

```sh
# Linux (requires libgssapi_krb5)
make GSSAPI=1

# macOS (uses the system GSS.framework — no extra package needed)
make GSSAPI=1
```

When enabled, the server accepts GSSAPI tokens via the standard two-byte-length-prefixed framing defined in RFC 1961, calls `gss_accept_sec_context()` in a loop until `GSS_S_COMPLETE`, and logs the authenticated Kerberos principal.

---

## Platform Notes

| Platform | Status | Notes |
|---|---|---|
| macOS | Supported | kqueue backend; GSS.framework for GSSAPI |
| Linux | Supported | epoll + `accept4()` + `splice()` zero-copy relay |
| FreeBSD / OpenBSD / NetBSD | Supported | kqueue backend |
| Windows | Supported | Winsock2; pthreads replaced with `_beginthread`; no kqueue/epoll fallback |

On Windows, link against `ws2_32.lib` (handled automatically by the Makefile when `OS=Windows_NT`).

---

## File Structure

```
socks5.c     — entire proxy implementation (~2400 lines)
tests.c      — C test suite (~565 lines)
Makefile     — build system
index.html   — project landing page
PLAN.md      — feature gap analysis and roadmap
LICENSE      — PolyForm Noncommercial 1.0.0
```

---

## License

Copyright (c) 2026 Interlaced Pixel.  
Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Free for non-commercial use; contact the author for commercial licensing.
