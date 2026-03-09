package drcom

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Packet codes.
const (
	CodeStartRequest   = 0x01
	CodeStartResponse  = 0x02
	CodeLoginAuth      = 0x03
	CodeLoginSuccess   = 0x04
	CodeLoginFailure   = 0x05
	CodeLogoutAuth     = 0x06
	CodeMisc           = 0x07
	CodeNotification   = 0x4d
	CodeAliveRequest   = 0xFF
)

// Misc step constants.
const (
	MiscStep1 = 0x01
	MiscStep3 = 0x03
	MiscStep4 = 0x04
	MiscFile  = 0x06
)

// Login failure reasons.
const (
	FailAlreadyOnline = 0x01
	FailWrongPassword = 0x03
	FailNoMoney       = 0x05
	FailWrongMAC      = 0x0b
)

// Default client version.
var DefaultClientVersion = [2]byte{0x1F, 0x00}

// MD5 checksum tail appended during login auth checksum computation.
var md5ChecksumTail = []byte{0x14, 0x00, 0x07, 0x0b}

// BuildStartRequest builds a 20-byte DrCOM start request.
func BuildStartRequest() []byte {
	pkt := make([]byte, 20)
	pkt[0] = CodeStartRequest
	// pkt[1] = 0x00 retry
	// pkt[2] = 0x00
	// pkt[3] = 0x00
	pkt[4] = 0x0a // version
	return pkt
}

// ParseStartResponse extracts the 4-byte challenge from a start response.
func ParseStartResponse(recv []byte) ([]byte, error) {
	if len(recv) < 8 {
		return nil, fmt.Errorf("start response too short: %d", len(recv))
	}
	if recv[0] != CodeStartResponse {
		return nil, fmt.Errorf("unexpected start response code: 0x%02x", recv[0])
	}
	challenge := make([]byte, 4)
	copy(challenge, recv[4:8])
	return challenge, nil
}

// LoginResult holds data extracted from a login success response.
type LoginResult struct {
	AuthInfo  []byte // 16 bytes, used for keep-alive
	TotalTime uint32 // minutes
	TotalFlux uint32 // bytes
	Balance   uint32
}

// FailureInfo holds data from a login failure response.
type FailureInfo struct {
	Reason byte
	IP     net.IP
	MAC    net.HardwareAddr
}

func (f *FailureInfo) Error() string {
	switch f.Reason {
	case FailAlreadyOnline:
		return fmt.Sprintf("already online at IP %s, MAC %s", f.IP, f.MAC)
	case FailWrongPassword:
		return "wrong username or password"
	case FailNoMoney:
		return "insufficient balance"
	case FailWrongMAC:
		return fmt.Sprintf("wrong MAC, expected %s", f.MAC)
	default:
		return fmt.Sprintf("unknown failure: 0x%02x", f.Reason)
	}
}

// ParseLoginResponse parses a login auth response.
func ParseLoginResponse(recv []byte) (*LoginResult, error) {
	if len(recv) < 39 {
		return nil, fmt.Errorf("login response too short: %d", len(recv))
	}

	if recv[0] == CodeLoginFailure {
		info := &FailureInfo{Reason: recv[4]}
		if len(recv) >= 15 {
			info.IP = net.IP(recv[5:9])
			info.MAC = net.HardwareAddr(recv[9:15])
		}
		return nil, info
	}

	if recv[0] != CodeLoginSuccess {
		return nil, fmt.Errorf("unexpected login response code: 0x%02x", recv[0])
	}

	r := &LoginResult{
		AuthInfo: make([]byte, 16),
	}
	copy(r.AuthInfo, recv[23:39])
	r.TotalTime = binary.LittleEndian.Uint32(recv[5:9])
	r.TotalFlux = binary.LittleEndian.Uint32(recv[9:13])
	r.Balance = binary.LittleEndian.Uint32(recv[13:17])
	return r, nil
}

// AliveInfo holds session info from an alive response.
type AliveInfo struct {
	OnlineTime uint32 // seconds
	TotalTime  uint32 // minutes
	TotalFlux  uint32 // bytes
	Balance    uint32
}

// ParseAliveResponse parses a keep-alive (0xFF) response.
func ParseAliveResponse(recv []byte) (*AliveInfo, error) {
	if len(recv) < 56 {
		return nil, fmt.Errorf("alive response too short: %d", len(recv))
	}
	return &AliveInfo{
		OnlineTime: binary.LittleEndian.Uint32(recv[32:36]),
		TotalTime:  binary.LittleEndian.Uint32(recv[44:48]),
		TotalFlux:  binary.LittleEndian.Uint32(recv[48:52]),
		Balance:    binary.LittleEndian.Uint32(recv[52:56]),
	}, nil
}

// FormatMAC formats a MAC byte slice as colon-separated hex.
func FormatMAC(mac []byte) string {
	if len(mac) < 6 {
		return "??:??:??:??:??:??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
