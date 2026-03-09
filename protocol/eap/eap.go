package eap

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/vanishcode/drcom-go/util"
)

const (
	snapLen    = 1518
	maxRetries = 2
	retryDelay = 2 * time.Second
)

var (
	ErrAuthFailure = errors.New("eap: authentication failure")
	log            = util.NewLogger(util.SectionEAP)
)

// Dealer handles 802.1X EAP authentication via pcap.
type Dealer struct {
	handle   *pcap.Handle
	localMAC net.HardwareAddr
	respID   []byte // identity payload for Response/Identity
	respMD5  []byte // identity payload for Response/MD5-Challenge
	password []byte

	// State received from gateway
	eapID        byte   // from Request/Identity
	md5EAPID     byte   // from Request/MD5-Challenge
	md5AttachKey []byte // challenge from Request/MD5-Challenge
}

// NewDealer creates an EAP dealer on the given NIC.
func NewDealer(nic string, localMAC net.HardwareAddr, localIP net.IP, username, password string, eapTimeout int) (*Dealer, error) {
	handle, err := pcap.OpenLive(nic, snapLen, true, time.Duration(eapTimeout)*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open %q: %w", nic, err)
	}

	if handle.LinkType() != 1 { // DLT_EN10MB
		handle.Close()
		return nil, fmt.Errorf("pcap: %q is not an Ethernet device", nic)
	}

	filter := fmt.Sprintf("ether dst %s and ether proto 0x888e", localMAC)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("pcap filter: %w", err)
	}

	ip4 := localIP.To4()

	// Response/Identity payload: username + [0x00, 0x44, 0x61, 0x00, 0x00] + IP
	respID := append([]byte(username), 0x00, 0x44, 0x61, 0x00, 0x00)
	respID = append(respID, ip4...)

	// Response/MD5 identity payload: username + [0x00, 0x44, 0x61, 0x0a, 0x00] + IP
	respMD5 := append([]byte(username), 0x00, 0x44, 0x61, 0x0a, 0x00)
	respMD5 = append(respMD5, ip4...)

	return &Dealer{
		handle:   handle,
		localMAC: localMAC,
		respID:   respID,
		respMD5:  respMD5,
		password: []byte(password),
	}, nil
}

// Close releases the pcap handle.
func (d *Dealer) Close() {
	d.handle.Close()
}

// sendAndRecv sends a frame and waits for a response.
func (d *Dealer) sendAndRecv(pkt []byte) ([]byte, error) {
	if err := d.handle.WritePacketData(pkt); err != nil {
		return nil, fmt.Errorf("pcap send: %w", err)
	}
	data, _, err := d.handle.ReadPacketData()
	if err != nil {
		return nil, fmt.Errorf("pcap recv: %w", err)
	}
	return data, nil
}

// Start sends EAPOL-Start and waits for Request/Identity.
func (d *Dealer) Start(gatewayMAC []byte) error {
	log.Info("Start")
	pkt := BuildEAPOLStart(gatewayMAC, d.localMAC)

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		recv, err := d.sendAndRecv(pkt)
		if err != nil {
			lastErr = err
			log.Warn("Start failed, retrying", "attempt", i+1, "err", err)
			time.Sleep(retryDelay)
			continue
		}

		hdr := ParseEAPHeaderFrom(recv)
		if hdr == nil || hdr.EAPOLType != EAPOLTypeEAPPacket {
			lastErr = fmt.Errorf("unexpected eapol_type: %d", safeType(hdr))
			continue
		}
		if hdr.EAPCode != EAPCodeRequest || hdr.EAPType != EAPTypeIdentity {
			lastErr = fmt.Errorf("unexpected eap code=%d type=%d", hdr.EAPCode, hdr.EAPType)
			continue
		}

		log.Info("Gateway returns: Request, Identity")
		d.eapID = hdr.EAPID
		return nil
	}
	return fmt.Errorf("eap start: %w", lastErr)
}

// ResponseIdentity sends Response/Identity and waits for Request/MD5-Challenge.
func (d *Dealer) ResponseIdentity(gatewayMAC []byte) error {
	log.Info("Response, Identity")
	pkt := BuildResponseIdentity(gatewayMAC, d.localMAC, d.eapID, d.respID)

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		recv, err := d.sendAndRecv(pkt)
		if err != nil {
			lastErr = err
			log.Warn("Response Identity failed, retrying", "attempt", i+1, "err", err)
			time.Sleep(retryDelay)
			continue
		}

		hdr := ParseEAPHeaderFrom(recv)
		if hdr == nil || hdr.EAPOLType != EAPOLTypeEAPPacket {
			lastErr = fmt.Errorf("unexpected eapol_type: %d", safeType(hdr))
			continue
		}
		if hdr.EAPCode != EAPCodeRequest || hdr.EAPType != EAPTypeMD5Challenge {
			lastErr = fmt.Errorf("unexpected eap code=%d type=%d", hdr.EAPCode, hdr.EAPType)
			continue
		}

		log.Info("Gateway returns: Request, MD5-Challenge")
		d.md5EAPID = hdr.EAPID
		d.md5AttachKey = make([]byte, MD5ValueSize)
		copy(d.md5AttachKey, hdr.MD5Value)
		return nil
	}
	return fmt.Errorf("eap response identity: %w", lastErr)
}

// ResponseMD5Challenge sends Response/MD5-Challenge and waits for Success.
func (d *Dealer) ResponseMD5Challenge(gatewayMAC []byte) error {
	log.Info("Response, MD5-Challenge")

	// MD5(eap_id + password + challenge)
	md5Input := make([]byte, 0, 1+len(d.password)+MD5ValueSize)
	md5Input = append(md5Input, d.md5EAPID)
	md5Input = append(md5Input, d.password...)
	md5Input = append(md5Input, d.md5AttachKey...)
	md5Sum := util.MD5Sum(md5Input)

	pkt := BuildResponseMD5Challenge(gatewayMAC, d.localMAC, d.md5EAPID, md5Sum[:], d.respMD5)

	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		recv, err := d.sendAndRecv(pkt)
		if err != nil {
			lastErr = err
			log.Warn("Response MD5-Challenge failed, retrying", "attempt", i+1, "err", err)
			time.Sleep(retryDelay)
			continue
		}

		hdr := ParseEAPHeaderFrom(recv)
		if hdr == nil || hdr.EAPOLType != EAPOLTypeEAPPacket {
			lastErr = fmt.Errorf("unexpected eapol_type: %d", safeType(hdr))
			continue
		}

		if hdr.EAPCode == EAPCodeRequest && hdr.EAPType == EAPTypeNotification {
			noti := ExtractNotification(recv)
			log.Info("Gateway notification", "msg", noti)

			if noti == "userid error1" {
				log.Info("Account does not exist")
			} else if noti == "userid error3" {
				log.Info("Account does not exist or has arrears")
			}

			d.Logoff(gatewayMAC)
			return ErrAuthFailure
		}

		if hdr.EAPCode == EAPCodeSuccess {
			log.Info("Gateway returns: Success")
			return nil
		}

		lastErr = fmt.Errorf("unexpected eap code=%d type=%d", hdr.EAPCode, hdr.EAPType)
	}
	return fmt.Errorf("eap md5 challenge: %w", lastErr)
}

// Logoff sends an EAPOL-Logoff frame. Errors are logged but not returned.
func (d *Dealer) Logoff(gatewayMAC []byte) {
	log.Info("Logoff")
	pkt := BuildEAPOLLogoff(gatewayMAC, d.localMAC)
	d.sendAndRecv(pkt) //nolint: best-effort
}

func safeType(h *EAPHeader) byte {
	if h == nil {
		return 0xFF
	}
	return h.EAPOLType
}
