package drcom

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestBuildStartRequest(t *testing.T) {
	pkt := BuildStartRequest()
	if len(pkt) != 20 {
		t.Fatalf("len(pkt) = %d, want 20", len(pkt))
	}
	if pkt[0] != CodeStartRequest {
		t.Fatalf("code = 0x%02x, want 0x%02x", pkt[0], CodeStartRequest)
	}
	if pkt[4] != 0x0a {
		t.Fatalf("version byte = 0x%02x, want 0x0a", pkt[4])
	}
}

func TestParseStartResponse(t *testing.T) {
	recv := []byte{CodeStartResponse, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}
	challenge, err := ParseStartResponse(recv)
	if err != nil {
		t.Fatalf("ParseStartResponse error: %v", err)
	}
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := range want {
		if challenge[i] != want[i] {
			t.Fatalf("challenge mismatch at %d: got 0x%02x, want 0x%02x", i, challenge[i], want[i])
		}
	}
}

func TestParseStartResponseErrors(t *testing.T) {
	if _, err := ParseStartResponse([]byte{CodeStartResponse}); err == nil {
		t.Fatal("expected short response error")
	}
	if _, err := ParseStartResponse([]byte{0x99, 0, 0, 0, 1, 2, 3, 4}); err == nil {
		t.Fatal("expected unexpected-code error")
	}
}

func TestParseLoginResponseSuccess(t *testing.T) {
	recv := make([]byte, 39)
	recv[0] = CodeLoginSuccess
	binary.LittleEndian.PutUint32(recv[5:9], 123)
	binary.LittleEndian.PutUint32(recv[9:13], 456)
	binary.LittleEndian.PutUint32(recv[13:17], 789)
	for i := 0; i < 16; i++ {
		recv[23+i] = byte(i + 1)
	}

	r, err := ParseLoginResponse(recv)
	if err != nil {
		t.Fatalf("ParseLoginResponse error: %v", err)
	}
	if r.TotalTime != 123 || r.TotalFlux != 456 || r.Balance != 789 {
		t.Fatalf("unexpected parsed counters: %+v", *r)
	}
	if len(r.AuthInfo) != 16 || r.AuthInfo[0] != 1 || r.AuthInfo[15] != 16 {
		t.Fatalf("unexpected auth info: %v", r.AuthInfo)
	}
}

func TestParseLoginResponseFailure(t *testing.T) {
	recv := make([]byte, 39)
	recv[0] = CodeLoginFailure
	recv[4] = FailAlreadyOnline
	copy(recv[5:9], net.IPv4(10, 0, 0, 8).To4())
	copy(recv[9:15], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	_, err := ParseLoginResponse(recv)
	if err == nil {
		t.Fatal("expected failure info error")
	}

	var fi *FailureInfo
	if !errors.As(err, &fi) {
		t.Fatalf("expected FailureInfo, got %T", err)
	}
	if fi.Reason != FailAlreadyOnline {
		t.Fatalf("reason = 0x%02x, want 0x%02x", fi.Reason, FailAlreadyOnline)
	}
	if fi.IP.String() != "10.0.0.8" {
		t.Fatalf("ip = %s, want 10.0.0.8", fi.IP)
	}
	if fi.MAC.String() != "00:11:22:33:44:55" {
		t.Fatalf("mac = %s, want 00:11:22:33:44:55", fi.MAC)
	}
}

func TestParseLoginResponseErrors(t *testing.T) {
	if _, err := ParseLoginResponse([]byte{CodeLoginSuccess}); err == nil {
		t.Fatal("expected short response error")
	}

	recv := make([]byte, 39)
	recv[0] = 0x42
	if _, err := ParseLoginResponse(recv); err == nil {
		t.Fatal("expected unexpected-code error")
	}
}

func TestParseAliveResponse(t *testing.T) {
	recv := make([]byte, 56)
	binary.LittleEndian.PutUint32(recv[32:36], 1000)
	binary.LittleEndian.PutUint32(recv[44:48], 2000)
	binary.LittleEndian.PutUint32(recv[48:52], 3000)
	binary.LittleEndian.PutUint32(recv[52:56], 4000)

	info, err := ParseAliveResponse(recv)
	if err != nil {
		t.Fatalf("ParseAliveResponse error: %v", err)
	}
	if info.OnlineTime != 1000 || info.TotalTime != 2000 || info.TotalFlux != 3000 || info.Balance != 4000 {
		t.Fatalf("unexpected alive info: %+v", *info)
	}
}

func TestParseAliveResponseShort(t *testing.T) {
	if _, err := ParseAliveResponse(make([]byte, 10)); err == nil {
		t.Fatal("expected short response error")
	}
}

func TestFormatMAC(t *testing.T) {
	if got := FormatMAC([]byte{0, 17, 34, 51, 68, 85}); got != "00:11:22:33:44:55" {
		t.Fatalf("FormatMAC = %q, want %q", got, "00:11:22:33:44:55")
	}
	if got := FormatMAC([]byte{1, 2}); got != "??:??:??:??:??:??" {
		t.Fatalf("FormatMAC short = %q, want placeholder", got)
	}
}
