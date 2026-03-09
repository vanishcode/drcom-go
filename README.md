# DrCOM-Go

A Go implementation of the DrCOM campus network authentication client for Harbin Institute of Technology (Weihai). Rewritten from [EasyDrcom](https://github.com/coverxit/EasyDrcom) (C++).

Supports EAP/802.1X authentication and DrCOM U31/U62 keep-alive protocols.

## Prerequisites

- Go 1.21+
- libpcap
  - **macOS**: included with Xcode Command Line Tools
  - **Debian/Ubuntu**: `sudo apt install libpcap-dev`
  - **RHEL/Fedora**: `sudo dnf install libpcap-devel`

## Build

```bash
go build -o drcom-go .
```

## Usage

```bash
# Run with default config (./config.yaml)
sudo ./drcom-go

# Run with custom config path
sudo ./drcom-go -c /path/to/config.yaml
```

Root/sudo is required for raw packet capture (802.1X).

### Interactive Commands

| Command   | Description              |
|-----------|--------------------------|
| `online`  | Connect to the network   |
| `offline` | Disconnect               |
| `quit`    | Disconnect and exit      |
| `help`    | Show available commands  |

If `AutoOnline=true` in config, the client connects automatically on startup.

## Configuration

Copy `config.yaml` and edit with your credentials:

```yaml
general:
  # Authentication mode: 0 = EAP + U31 (dormitory), 1 = U31 only, 2 = EAP + U62
  mode: 0
  username: "150420201"
  password: "password"
  # Auto connect on startup
  auto_online: true
  # Auto reconnect on disconnect
  auto_redial: true

local:
  # Network interface name (e.g., en0 on macOS, eth0 on Linux)
  nic: en0
  hostname: "EasyDrcom for HITwh"
  kernel_version: "v0.9"
  # EAP pcap read timeout in milliseconds
  eap_timeout: 1000
  # UDP socket read timeout in milliseconds
  udp_timeout: 2000

remote:
  # DrCOM gateway IP
  ip: "172.25.8.4"
  # DrCOM gateway port
  port: 61440
  # Use broadcast MAC for EAP (true for most setups)
  use_broadcast: true
  # Gateway MAC (required only if use_broadcast is false)
  # mac: "00:1a:a9:c3:3a:59"
```

### Authentication Modes

| Mode | Protocol     | Use Case                          |
|------|--------------|-----------------------------------|
| 0    | EAP + U31    | Dormitory (802.1X + full DrCOM)   |
| 1    | U31 only     | No EAP required                   |
| 2    | EAP + U62    | Dormitory (802.1X + keep-alive only) |

## Project Structure

```
main.go                    CLI entry point, command loop
config/config.go           YAML config parsing
session/session.go         State machine, online/offline orchestration
protocol/
  eap/
    packet.go              EAP frame constants and builders
    eap.go                 802.1X EAP authentication (pcap-based)
  drcom/
    drcom.go               DrCOMDealer interface
    packet.go              Shared packet constants and parsers
    u31.go                 U31 full protocol (login + keep-alive)
    u62.go                 U62 keep-alive only
  udp/
    udp.go                 UDP transport with timeout and retry
util/
  md5.go                   MD5 convenience wrapper
  net.go                   NIC MAC/IP retrieval
  hex.go                   Hex dump for debug logging
  log.go                   Structured logger with section prefixes
```

## License

Based on [EasyDrcom](https://github.com/coverxit/EasyDrcom), licensed under the Apache License 2.0.
