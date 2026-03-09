package drcom

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vanishcode/drcom-go/protocol/udp"
	"github.com/vanishcode/drcom-go/util"
)

var u62Log = util.NewLogger(util.SectionU62)

// U62Dealer implements the DrCOM U62.R0 protocol (keep-alive only).
type U62Dealer struct {
	udp           *udp.Dealer
	localMAC      net.HardwareAddr
	localIP       net.IP
	clientVersion [2]byte
	pktID         byte
	misc1Flux     uint32
	misc3Flux     uint32
}

// NewU62Dealer creates a U62 dealer.
func NewU62Dealer(mac net.HardwareAddr, ip net.IP, gatewayIP string, gatewayPort int, udpTimeout int) (*U62Dealer, error) {
	u, err := udp.NewDealer(gatewayIP, gatewayPort, ip.String(), udpTimeout)
	if err != nil {
		return nil, err
	}

	return &U62Dealer{
		udp:           u,
		localMAC:      mac,
		localIP:       ip.To4(),
		clientVersion: DefaultClientVersion,
	}, nil
}

// Close closes the underlying UDP connection.
func (d *U62Dealer) Close() error {
	return d.udp.Close()
}

// SendAlivePkt1 sends keep-alive misc packet 1 (step 0x01).
func (d *U62Dealer) SendAlivePkt1() error {
	return d.sendAlivePkt1(0)
}

func (d *U62Dealer) sendAlivePkt1(retryCount int) error {
	u62Log.Info("Send Alive Packet 1")

	pkt := make([]byte, 40)
	pkt[0] = CodeMisc
	pkt[1] = d.pktID
	pkt[2] = 0x28
	pkt[3] = 0x00
	pkt[4] = 0x0B
	pkt[5] = MiscStep1
	copy(pkt[6:8], d.clientVersion[:])
	pkt[8] = 0xDE
	pkt[9] = 0xAD
	binary.LittleEndian.PutUint32(pkt[16:20], d.misc1Flux)
	// bytes 28-31: client IP = 0.0.0.0

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("alive pkt1: %w", err)
	}

	if recv[0] != CodeMisc {
		return fmt.Errorf("alive pkt1: unexpected code 0x%02x", recv[0])
	}

	if recv[5] == MiscFile {
		u62Log.Info("Received Misc File, retrying")
		copy(d.clientVersion[:], recv[6:8])
		if retryCount < 10 {
			return d.sendAlivePkt1(retryCount + 1)
		}
		return fmt.Errorf("alive pkt1: too many File retries")
	}

	u62Log.Info("Gateway returns: Response for Alive Packet 1")
	d.pktID++
	if len(recv) >= 20 {
		d.misc3Flux = binary.LittleEndian.Uint32(recv[16:20])
	}
	return nil
}

// SendAlivePkt2 sends keep-alive misc packet 2 (step 0x03).
func (d *U62Dealer) SendAlivePkt2() error {
	u62Log.Info("Send Alive Packet 2")

	pkt := make([]byte, 40)
	pkt[0] = CodeMisc
	pkt[1] = d.pktID
	pkt[2] = 0x28
	pkt[3] = 0x00
	pkt[4] = 0x0B
	pkt[5] = MiscStep3
	copy(pkt[6:8], d.clientVersion[:])
	pkt[8] = 0xDE
	pkt[9] = 0xAD
	binary.LittleEndian.PutUint32(pkt[16:20], d.misc3Flux)
	copy(pkt[28:32], d.localIP) // Client IP

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("alive pkt2: %w", err)
	}

	if recv[0] != CodeMisc {
		return fmt.Errorf("alive pkt2: unexpected code 0x%02x", recv[0])
	}

	u62Log.Info("Gateway returns: Response for Alive Packet 2")
	d.pktID++
	if len(recv) >= 20 {
		d.misc1Flux = binary.LittleEndian.Uint32(recv[16:20])
	}
	return nil
}
