package eap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildEtherHeader(t *testing.T) {
	dst := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	src := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	h := BuildEtherHeader(dst, src)
	if len(h) != EtherHeaderLen {
		t.Fatalf("len(header) = %d, want %d", len(h), EtherHeaderLen)
	}
	if !bytes.Equal(h[0:6], dst) {
		t.Fatalf("dst MAC mismatch: got %x, want %x", h[0:6], dst)
	}
	if !bytes.Equal(h[6:12], src) {
		t.Fatalf("src MAC mismatch: got %x, want %x", h[6:12], src)
	}
	if got := binary.BigEndian.Uint16(h[12:14]); got != EtherType8021X {
		t.Fatalf("ethertype = 0x%04x, want 0x%04x", got, EtherType8021X)
	}
}

func TestBuildEAPOLStartAndLogoff(t *testing.T) {
	dst := []byte{1, 2, 3, 4, 5, 6}
	src := []byte{6, 5, 4, 3, 2, 1}

	start := BuildEAPOLStart(dst, src)
	if len(start) != FrameSize {
		t.Fatalf("start len = %d, want %d", len(start), FrameSize)
	}
	if start[EtherHeaderLen] != 0x01 || start[EtherHeaderLen+1] != EAPOLTypeStart {
		t.Fatalf("unexpected start header bytes: %x %x", start[EtherHeaderLen], start[EtherHeaderLen+1])
	}

	logoff := BuildEAPOLLogoff(dst, src)
	if len(logoff) != FrameSize {
		t.Fatalf("logoff len = %d, want %d", len(logoff), FrameSize)
	}
	if logoff[EtherHeaderLen] != 0x01 || logoff[EtherHeaderLen+1] != EAPOLTypeLogoff {
		t.Fatalf("unexpected logoff header bytes: %x %x", logoff[EtherHeaderLen], logoff[EtherHeaderLen+1])
	}
}

func TestBuildResponseIdentity(t *testing.T) {
	dst := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	src := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	respID := []byte("alice\x00Da\x00\x00\x0a\x00\x00\x01")

	pkt := BuildResponseIdentity(dst, src, 0x42, respID)
	off := EtherHeaderLen
	wantEAPLen := uint16(5 + len(respID))

	if len(pkt) != FrameSize {
		t.Fatalf("len(pkt) = %d, want %d", len(pkt), FrameSize)
	}
	if pkt[off+1] != EAPOLTypeEAPPacket {
		t.Fatalf("eapol type = %d, want %d", pkt[off+1], EAPOLTypeEAPPacket)
	}
	if got := binary.BigEndian.Uint16(pkt[off+2 : off+4]); got != wantEAPLen {
		t.Fatalf("eapol length = %d, want %d", got, wantEAPLen)
	}
	if pkt[off+4] != EAPCodeResponse || pkt[off+5] != 0x42 || pkt[off+8] != EAPTypeIdentity {
		t.Fatalf("unexpected eap header code=%d id=%d type=%d", pkt[off+4], pkt[off+5], pkt[off+8])
	}
	if !bytes.Equal(pkt[off+9:off+9+len(respID)], respID) {
		t.Fatalf("identity payload mismatch")
	}
}

func TestBuildResponseMD5ChallengeAndParse(t *testing.T) {
	dst := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	src := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	md5Value := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	extra := []byte("alice")

	pkt := BuildResponseMD5Challenge(dst, src, 0x7f, md5Value, extra)
	off := EtherHeaderLen
	wantEAPLen := uint16(6 + MD5ValueSize + len(extra))

	if got := binary.BigEndian.Uint16(pkt[off+2 : off+4]); got != wantEAPLen {
		t.Fatalf("eapol length = %d, want %d", got, wantEAPLen)
	}
	if pkt[off+4] != EAPCodeResponse || pkt[off+5] != 0x7f || pkt[off+8] != EAPTypeMD5Challenge {
		t.Fatalf("unexpected eap header code=%d id=%d type=%d", pkt[off+4], pkt[off+5], pkt[off+8])
	}
	if pkt[off+9] != MD5ValueSize {
		t.Fatalf("md5 size byte = %d, want %d", pkt[off+9], MD5ValueSize)
	}
	if !bytes.Equal(pkt[off+10:off+10+MD5ValueSize], md5Value) {
		t.Fatalf("md5 value mismatch")
	}
	if !bytes.Equal(pkt[off+10+MD5ValueSize:off+10+MD5ValueSize+len(extra)], extra) {
		t.Fatalf("extra payload mismatch")
	}

	h := ParseEAPHeaderFrom(pkt)
	if h == nil {
		t.Fatal("ParseEAPHeaderFrom returned nil")
	}
	if h.EAPOLType != EAPOLTypeEAPPacket || h.EAPCode != EAPCodeResponse || h.EAPID != 0x7f || h.EAPType != EAPTypeMD5Challenge {
		t.Fatalf("unexpected parsed header: %+v", *h)
	}
	if !bytes.Equal(h.MD5Value, md5Value) {
		t.Fatalf("parsed md5 mismatch: got %x, want %x", h.MD5Value, md5Value)
	}
}

func TestParseEAPHeaderFromTooShort(t *testing.T) {
	if h := ParseEAPHeaderFrom([]byte{1, 2, 3}); h != nil {
		t.Fatalf("expected nil for short frame, got %+v", h)
	}
}

func TestExtractNotification(t *testing.T) {
	msg := []byte("userid error1")
	pkt := make([]byte, EtherHeaderLen+9+len(msg))
	off := EtherHeaderLen
	binary.BigEndian.PutUint16(pkt[off+6:off+8], uint16(5+len(msg)))
	copy(pkt[off+9:], msg)

	if got := ExtractNotification(pkt); got != string(msg) {
		t.Fatalf("notification = %q, want %q", got, msg)
	}
}

func TestExtractNotificationWithShortFrame(t *testing.T) {
	if got := ExtractNotification([]byte{1, 2, 3}); got != "" {
		t.Fatalf("notification = %q, want empty", got)
	}
}

func TestSafeType(t *testing.T) {
	if got := safeType(nil); got != 0xFF {
		t.Fatalf("safeType(nil) = 0x%02x, want 0xFF", got)
	}
	if got := safeType(&EAPHeader{EAPOLType: 0x01}); got != 0x01 {
		t.Fatalf("safeType(header) = 0x%02x, want 0x01", got)
	}
}
