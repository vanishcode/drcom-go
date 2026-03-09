# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build & Run

```bash
go build ./...            # compile all packages
go vet ./...              # static analysis
go run . -c config.yaml   # run with config
```

**Requirements:** Go 1.26+, libpcap (pcap headers) — on macOS included with Xcode CLT; on Linux install `libpcap-dev`.

**Dependencies:** `github.com/google/gopacket` (packet capture), `gopkg.in/yaml.v3` (config parsing).

## Architecture

Go rewrite of EasyDrcom (`github.com/vanishcode/drcom-go`), a DrCOM campus network authentication client for HIT Weihai. Implements EAP/802.1X + DrCOM U31/U62 protocols.

**Dependency flow:**

```
main.go → session → protocol/{eap, drcom, udp} → util
                  → config → util
```

- **`main.go`** — Entry point. Interactive CLI with commands: `online`, `offline`, `quit`, `help`. Config path via `-c` flag (default `config.yaml`). Supports auto-connect on start.
- **`session/`** — State machine (`Offline → OnlineProcessing → Online → OfflineProcessing → Offline`). Uses `context.Context` for goroutine cancellation and a 20-second keep-alive ticker. Auto-redial on connection loss (5s retry delay).
- **`protocol/eap/`** — 802.1X EAP authentication via libpcap/gopacket. `packet.go` builds raw Ethernet frames; `eap.go` runs the handshake (Start → Identity → MD5-Challenge → Success) and logoff.
- **`protocol/drcom/`** — Two protocol dialects sharing the `DrCOMDealer` interface (`SendAlivePkt1`, `SendAlivePkt2`, `Close`). `U31Dealer` does full login/logout + keep-alive; `U62Dealer` does keep-alive only. `packet.go` has shared constants and response parsers.
- **`protocol/udp/`** — UDP transport with `SetReadDeadline` timeout and retry (max 2 retries, 2s delay, 2048-byte buffer).
- **`config/`** — YAML parsing via `yaml.v3`. Auto-discovers NIC MAC/IP via `util.GetNICAddrs`. Supports fake credentials for testing via `Effective*()` methods.
- **`util/`** — Shared helpers: `log.go` (slog-based structured logger with section tags), `net.go` (NIC address discovery), `hex.go` (hex dump for debugging), `md5.go` (MD5 digest wrapper).

**Auth mode mapping** (`General.Mode` in config):
- `0` = EAP + U31 (dormitory)
- `1` = U31 only (no EAP)
- `2` = EAP + U62

## Protocol Notes

The DrCOM protocol uses specific byte-level packet formats. Key packet builders are in `protocol/drcom/u31.go:buildLoginPacket` and `protocol/eap/packet.go`. When modifying packet construction, compare against the C++ reference at `../EasyDrcom/EasyDrcom/` (the original implementation this was ported from).
