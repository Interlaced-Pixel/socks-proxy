# SOCKS5 Proxy Server Analysis & Improvement Plan

This document summarizes the current state of the SOCKS5 proxy server implementation, identifies functional gaps, and proposes a roadmap for achieving full protocol compliance and operational robustness.

## Feature Gap Analysis

### [x] Implemented
- **Standard SOCKS5 Handshake**: Version negotiation and method selection.
- **CONNECT Command**: Core TCP proxying functionality.
- **Addressing**: Support for IPv4 and Domain Name destination addresses.
- **Authentication**: `NO AUTH` and `USERNAME/PASSWORD` (RFC 1929) logic.
- **Cross-Platform**: Threading and socket abstraction for and Windows/Linux/macOS.
- **Bidirectional Relay**: Efficient data transfer using `select()`.
- **IPv6 Support**: Fully supported, including correct BND.ADDR handling in replies.
- **RFC Compliance**: Server correctly asserts bind address/port in CONNECT replies.
- **Handshake Timeouts**: `SO_RCVTIMEO` and `SO_SNDTIMEO` applied to prevent resource exhaustion.
- **Tests**: Basic Python test suite (`tests.py`) covering handshake, CONNECT, and command acceptance.

### [/] Incomplete / Partially Implemented
- **Authentication Backend**: The framework exists (`auth_cb`), but the default executable does not provide a functional implementation or user database.

### [ ] Missing Features
- **BIND Command**: Stubs added (returns COMMAND_NOT_SUPPORTED), logic not implemented.
- **UDP ASSOCIATE Command**: Stubs added (returns COMMAND_NOT_SUPPORTED), logic not implemented.
- **GSSAPI Authentication**: Not supported.
- **Advanced CLI**: No command-line arguments for:
  - Specifying bind address (fixed to `0.0.0.0`).
  - Enabling/disabling authentication.
  - Adding users (currently requires code modification).
- **Security Hardening**:
  - No connection limiting (maximum concurrent sessions).
  - No IP access control lists (ACLs).
- **Observability**:
  - No timestamps in logs.
  - No session statistics (bytes transferred, duration).

---

## Proposed Changes

### [Component] CLI & UX
#### [MODIFY] [socks5.c](socks5.c)
- Replace basic `argc/argv` handling with a robust argument parser (or simple `getopt` loop).
- Add `--bind`, `--auth`, and `--user` flags.

### [Component] Testing
#### [MODIFY] [tests.py]
- Expand coverage for new CLI options and auth scenarios.

## Verification Plan

### Automated Tests
- Run `make` to ensure it compiles.
- Execute newly created `tests.py` against the running `socks5` binary.

### Manual Verification
- Use `curl --socks5-hostname localhost:1080 http://example.com` to verify basic connectivity.
- Verify log output shows correct target information.
