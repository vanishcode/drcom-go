package eap

import "encoding/binary"

// Frame and header sizes.
const (
	FrameSize      = 0x60 // 96 bytes
	MD5ValueSize   = 0x10 // 16 bytes
	EtherAddrLen   = 6
	EtherHeaderLen = 14
	EtherType8021X = 0x888e
)

// EAPOL types.
const (
	EAPOLTypeEAPPacket = 0x00
	EAPOLTypeStart     = 0x01
	EAPOLTypeLogoff    = 0x02
)

// EAP codes.
const (
	EAPCodeRequest  = 0x01
	EAPCodeResponse = 0x02
	EAPCodeSuccess  = 0x03
	EAPCodeFailure  = 0x04
)

// EAP types.
const (
	EAPTypeIdentity     = 0x01
	EAPTypeNotification = 0x02
	EAPTypeMD5Challenge = 0x04
)

// BuildEtherHeader builds a 14-byte Ethernet header for 802.1X.
func BuildEtherHeader(dstMAC, srcMAC []byte) []byte {
	hdr := make([]byte, EtherHeaderLen)
	copy(hdr[0:6], dstMAC)
	copy(hdr[6:12], srcMAC)
	binary.BigEndian.PutUint16(hdr[12:14], EtherType8021X)
	return hdr
}

// BuildEAPOLStart builds a 96-byte EAPOL-Start frame.
func BuildEAPOLStart(dstMAC, srcMAC []byte) []byte {
	pkt := make([]byte, FrameSize)
	copy(pkt, BuildEtherHeader(dstMAC, srcMAC))
	pkt[EtherHeaderLen] = 0x01   // Version: 802.1X-2001
	pkt[EtherHeaderLen+1] = EAPOLTypeStart
	// Length = 0x0000
	return pkt
}

// BuildEAPOLLogoff builds a 96-byte EAPOL-Logoff frame.
func BuildEAPOLLogoff(dstMAC, srcMAC []byte) []byte {
	pkt := make([]byte, FrameSize)
	copy(pkt, BuildEtherHeader(dstMAC, srcMAC))
	pkt[EtherHeaderLen] = 0x01   // Version: 802.1X-2001
	pkt[EtherHeaderLen+1] = EAPOLTypeLogoff
	// Length = 0x0000
	return pkt
}

// BuildResponseIdentity builds an EAP Response/Identity frame.
// respID is the identity payload (username + suffix + IP).
func BuildResponseIdentity(dstMAC, srcMAC []byte, eapID byte, respID []byte) []byte {
	pkt := make([]byte, FrameSize)
	copy(pkt, BuildEtherHeader(dstMAC, srcMAC))

	off := EtherHeaderLen
	pkt[off] = 0x01              // Version
	pkt[off+1] = EAPOLTypeEAPPacket

	eapLen := uint16(5 + len(respID)) // 5 = code(1) + id(1) + length(2) + type(1)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], eapLen) // EAPOL length
	pkt[off+4] = EAPCodeResponse
	pkt[off+5] = eapID
	binary.BigEndian.PutUint16(pkt[off+6:off+8], eapLen) // EAP length
	pkt[off+8] = EAPTypeIdentity

	copy(pkt[off+9:], respID)
	return pkt
}

// BuildResponseMD5Challenge builds an EAP Response/MD5-Challenge frame.
// md5Value is the 16-byte MD5 response, extraData is the trailing identity.
func BuildResponseMD5Challenge(dstMAC, srcMAC []byte, eapID byte, md5Value []byte, extraData []byte) []byte {
	pkt := make([]byte, FrameSize)
	copy(pkt, BuildEtherHeader(dstMAC, srcMAC))

	off := EtherHeaderLen
	pkt[off] = 0x01              // Version
	pkt[off+1] = EAPOLTypeEAPPacket

	// EAP length = code(1) + id(1) + len(2) + type(1) + md5size(1) + md5(16) + extra
	eapLen := uint16(6 + MD5ValueSize + len(extraData))
	binary.BigEndian.PutUint16(pkt[off+2:off+4], eapLen)
	pkt[off+4] = EAPCodeResponse
	pkt[off+5] = eapID
	binary.BigEndian.PutUint16(pkt[off+6:off+8], eapLen)
	pkt[off+8] = EAPTypeMD5Challenge
	pkt[off+9] = MD5ValueSize

	copy(pkt[off+10:off+10+MD5ValueSize], md5Value)
	copy(pkt[off+10+MD5ValueSize:], extraData)
	return pkt
}

// ParseEAPHeader extracts key fields from a received EAP frame.
type EAPHeader struct {
	EAPOLType    byte
	EAPCode      byte
	EAPID        byte
	EAPLength    uint16
	EAPType      byte
	MD5ValueSize byte
	MD5Value     []byte
}

// ParseEAPHeader parses the EAP header from raw Ethernet frame bytes.
func ParseEAPHeaderFrom(data []byte) *EAPHeader {
	if len(data) < EtherHeaderLen+10 {
		return nil
	}
	off := EtherHeaderLen
	h := &EAPHeader{
		EAPOLType: data[off+1],
		EAPCode:   data[off+4],
		EAPID:     data[off+5],
		EAPLength: binary.BigEndian.Uint16(data[off+6 : off+8]),
		EAPType:   data[off+8],
	}
	if len(data) >= off+10+MD5ValueSize {
		h.MD5ValueSize = data[off+9]
		h.MD5Value = make([]byte, MD5ValueSize)
		copy(h.MD5Value, data[off+10:off+10+MD5ValueSize])
	}
	return h
}

// ExtractNotification extracts a notification string from an EAP packet.
func ExtractNotification(data []byte) string {
	off := EtherHeaderLen
	if len(data) < off+9 {
		return ""
	}
	eapLen := binary.BigEndian.Uint16(data[off+6 : off+8])
	if eapLen <= 5 {
		return ""
	}
	msgLen := int(eapLen) - 5
	start := off + 9
	if start+msgLen > len(data) {
		msgLen = len(data) - start
	}
	return string(data[start : start+msgLen])
}
