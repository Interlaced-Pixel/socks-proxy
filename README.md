# socks-proxy

A lightweight, single-file SOCKS5 proxy server written in C. Supports CONNECT, BIND, and UDP ASSOCIATE commands with optional username/password authentication and basic security features.

## Building

Requires a C11-compatible compiler (clang or gcc) and pthreads.

```sh
make
```

## Usage

```sh
./socks5 [options] [port]
```

### Options

| Flag | Description |
|---|---|
| `-p, --port <port>` | Port to listen on (default: 1080) |
| `-b, --bind <ip>` | Bind address (default: 0.0.0.0) |
| `-u, --user <user:pass>` | Add user credentials (enables auth). Repeatable. |
| `--max-conn <n>` | Max concurrent connections (default: 100) |
| `--allow-ip <ip>` | Restrict access to specific client IPs. Repeatable. |
| `-d, --debug` | Enable verbose debug logging |
| `--install <mode>` | Install as a service (`systemd`) or to a path |
| `--uninstall <mode>` | Uninstall service (`systemd`) or from a path |
| `-h, --help` | Show help |
| `-V, --version` | Show program version |

### Examples

```sh
# Start on default port (1080), no authentication
./socks5

# Start on port 8080 with authentication
./socks5 -p 8080 -u admin:secret

# Multiple users, restricted to specific client IPs
./socks5 -u alice:pass1 -u bob:pass2 --allow-ip 192.168.1.10 --allow-ip 10.0.0.5

# Limit concurrent connections
./socks5 --max-conn 500
```

### Using with curl

```sh
curl --socks5-hostname localhost:1080 http://example.com
```

### Installing as a systemd service (Linux)

```sh
sudo ./socks5 --install systemd
```

Edit `/etc/systemd/system/socks5.service` to adjust `ExecStart` arguments (port, users, etc.), then:

```sh
sudo systemctl daemon-reload
sudo systemctl restart socks5
```

To uninstall:

```sh
sudo ./socks5 --uninstall systemd
```

## Features

- **SOCKS5 protocol** — CONNECT, BIND, and UDP ASSOCIATE commands
- **Authentication** — No-auth and username/password (RFC 1929)
- **IPv4 & IPv6** — Full dual-stack support
- **IP allowlisting** — Restrict which client IPs may connect
- **Connection limits** — Cap concurrent connections
- **Session logging** — Timestamped logs with per-session byte/duration stats
- **Cross-platform** — Builds on Linux, macOS, and Windows

## Testing

Tests include a C-based test suite in `tests.c`.
 
 ```sh
 make check
 ```

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for non-commercial use. Contact the author for commercial licensing.
