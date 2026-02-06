# socks-proxy

A lightweight, standalone, cross-platform SOCKS5 proxy server implemented in a single C file.

## Overview

This project provides a single-file implementation of the SOCKS5 protocol (RFC 1928). It is designed to be easily embeddable or usable as a standalone proxy utility. The server supports `CONNECT`, `BIND`, and `UDP ASSOCIATE` commands with optional username/password authentication.

## Features

- **Protocol Support**: SOCKS5 (RFC 1928).
- **Authentication**:
  - `NO AUTHENTICATION REQUIRED`
  - `USERNAME/PASSWORD` (RFC 1929)
- **Commands**: `CONNECT`, `BIND`, and `UDP ASSOCIATE`.
- **Addressing**: IPv4, IPv6, and Domain Names.
- **Cross-Platform**: Compiles and runs on macOS, Linux, and Windows (MinGW/MSVC).
- **Concurrency**: Threaded handling for each client connection.
- **Security**: IP allowlisting, configurable max connections.
- **Self-Installing**: The binary can install itself (and an embedded systemd unit)

## Building and Running

### Prerequisites
- GCC or Clang
- Make (optional, but recommended)

### Build
```bash
make
```

### Run
Start the server on the default port (1080):
```bash
./socks5
```

Specify a custom port:
```bash
./socks5 --port 8888
# or shorthand:
./socks5 8888
```

## Usage

```
Usage: ./socks5 [options] [port]

Options:
  -p, --port <port>        Port to listen on (default: 1080)
  -b, --bind <ip>          Bind address (default: 0.0.0.0)
  -u, --user <user:pass>   Add user (enables auth). Can be used multiple times.
  --max-conn <n>           Max concurrent connections (default: 100)
  --allow-ip <ip>          Allow only specific IP (can be used multiple times)
  --install <mode>         Install the service (mode: systemd/service, or a path)
  --uninstall <mode>       Uninstall the service (mode: systemd/service, or a path)
  -h, --help               Show help message
```

### Examples

Listen on port 9090 with authentication:
```bash
./socks5 --port 9090 --user alice:secret --user bob:hunter2
```

Restrict to specific client IPs:
```bash
./socks5 --allow-ip 192.168.1.10 --allow-ip 10.0.0.5
```

## Installation

The binary installs itself from memory — no separate files need to exist on disk.

### systemd (Linux)

Install the binary to `/usr/local/bin` and write the embedded systemd unit to `/etc/systemd/system/socks5.service`:
```bash
sudo ./socks5 --install systemd
```

This will also run `systemctl daemon-reload` and enable/start the service.

### Custom path

Install the binary to any directory or file path:
```bash
./socks5 --install /opt/bin/
```

### Uninstall

Remove the systemd service and installed binary:
```bash
sudo ./socks5 --uninstall systemd
```

Or remove from a custom path:
```bash
./socks5 --uninstall /opt/bin/socks5
```

## Known Limitations

- **IPv6**: Parsing and connecting over IPv6 works, but some reply paths fall back to an IPv4 placeholder address.
- **Authentication**: GSSAPI is not supported.
- **UDP ASSOCIATE**: Supports IPv4, IPv6, and domain-name targets (domain names are resolved at relay time).
- **Install**: The `--install` and `--uninstall` options are not supported on Windows.
