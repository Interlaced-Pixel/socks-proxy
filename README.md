# socks-proxy

A lightweight, standalone, cross-platform SOCKS5 proxy server implemented in C.

## Overview

This project provides a single-file implementation of the SOCKS5 protocol (RFC 1928). It is designed to be easily embeddable or usable as a standalone proxy utility. The server supports basic `CONNECT` commands and multiple authentication methods.

## Features

- **Protocol Support**: SOCKS5 (RFC 1928).
- **Authentication**:
  - `NO AUTHENTICATION REQUIRED`
  - `USERNAME/PASSWORD` (RFC 1929)
- **Commands**: `CONNECT` (TCP proxying).
- **Addressing**: IPv4 and Domain Names.
- **Cross-Platform**: Compiles and runs on macOS, Linux, and Windows (MinGW/MSVC).
- **Concurrency**: Threaded handling for each client connection.

## Building and Running

### Prerequisites
- GCC or Clang
- Make (optional, but recommended)

### Build
Run `make` to build the `socks5` executable:
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
./socks5 8888
```

## Configuration

Currently, configuration is handled via code or minimal CLI arguments:
- **Port**: 1st argument (default: 1080).
- **Bind Address**: Hardcoded to `0.0.0.0` (all interfaces).
- **Authentication**: Disabled by default in the provided `main()` (can be enabled by modifying `socks5_config`).
- **Logging**: stdout.

## Missing Features / Known Limitations

Based on a recent codebase analysis, the following features are currently missing or incomplete:

- **Commands**:
  - `BIND` is not supported.
  - `UDP ASSOCIATE` is not supported.
- **IPv6**: Logic for parsing IPv6 exists, but the server's reply currently returns a placeholder IPv4 address.
- **Authentication**: GSSAPI is not supported.
- **CLI**: No flags for configuring user accounts, bind address, or toggling auth without recompiling.
- **Security**: No access control lists (ACLs) or rate limiting.
