package drcom

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vanishcode/drcom-go/protocol/udp"
	"github.com/vanishcode/drcom-go/util"
)

var u31Log = util.NewLogger(util.SectionU31)

// U31Dealer implements the DrCOM U31.R0 protocol (full login + keep-alive).
type U31Dealer struct {
	udp           *udp.Dealer
	localMAC      net.HardwareAddr
	localIP       net.IP
	username      string
	password      string
	hostname      string
	kernelVersion string

	// State
	challenge     []byte
	loginMD5A     []byte
	authInfo      []byte
	totalTime     uint32
	totalFlux     uint32
	balance       uint32
	onlineTime    uint32
	clientVersion [2]byte
	pktID         byte
	misc1Flux     uint32
	misc3Flux     uint32
}

// NewU31Dealer creates a U31 dealer.
func NewU31Dealer(mac net.HardwareAddr, ip net.IP, username, password, gatewayIP string, gatewayPort int, hostname, kernelVersion string, udpTimeout int) (*U31Dealer, error) {
	u, err := udp.NewDealer(gatewayIP, gatewayPort, ip.String(), udpTimeout)
	if err != nil {
		return nil, err
	}

	return &U31Dealer{
		udp:           u,
		localMAC:      mac,
		localIP:       ip.To4(),
		username:      username,
		password:      password,
		hostname:      hostname,
		kernelVersion: kernelVersion,
		clientVersion: DefaultClientVersion,
	}, nil
}

// Close closes the underlying UDP connection.
func (d *U31Dealer) Close() error {
	return d.udp.Close()
}

// StartRequest sends a start request and extracts the challenge.
func (d *U31Dealer) StartRequest() error {
	u31Log.Info("Start Request")
	pkt := BuildStartRequest()

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("start request: %w", err)
	}

	if recv[0] == CodeNotification {
		u31Log.Info("Received Notification, retrying Start Request")
		return d.StartRequest()
	}

	challenge, err := ParseStartResponse(recv)
	if err != nil {
		return err
	}

	u31Log.Info("Gateway returns: Start Response")
	d.challenge = challenge
	return nil
}

// SendLoginAuth builds and sends the login auth packet.
func (d *U31Dealer) SendLoginAuth() (*LoginResult, error) {
	if len(d.challenge) == 0 {
		return nil, fmt.Errorf("no challenge available")
	}

	u31Log.Info("Send Login Auth")

	pkt := d.buildLoginPacket(CodeLoginAuth)

	u31Log.Debug("login packet", "dump", util.HexDump(pkt))

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return nil, fmt.Errorf("login auth: %w", err)
	}

	u31Log.Debug("login response", "dump", util.HexDump(recv))

	result, err := ParseLoginResponse(recv)
	if err != nil {
		return nil, err
	}

	d.authInfo = result.AuthInfo
	d.totalTime = result.TotalTime
	d.totalFlux = result.TotalFlux
	d.balance = result.Balance

	u31Log.Info("Login auth succeeded",
		"usedTime", fmt.Sprintf("%d min", result.TotalTime),
		"usedFlux", fmt.Sprintf("%.2f MB", float64(result.TotalFlux)/1024.0),
		"balance", fmt.Sprintf("%.2f RMB", float64(result.Balance)/100.0))

	return result, nil
}

// SendAliveRequest sends the 0xFF alive request packet.
func (d *U31Dealer) SendAliveRequest() (*AliveInfo, error) {
	if len(d.loginMD5A) == 0 || len(d.authInfo) == 0 {
		return nil, fmt.Errorf("not authenticated")
	}

	u31Log.Info("Send Alive Request")

	pkt := make([]byte, 0, 38)
	pkt = append(pkt, CodeAliveRequest)
	pkt = append(pkt, d.loginMD5A...)
	pkt = append(pkt, 0x00, 0x00, 0x00) // padding
	pkt = append(pkt, d.authInfo...)
	// timestamp (2 bytes, seconds within day)
	now := uint16(time.Now().Unix() % 86400)
	pkt = append(pkt, byte(now), byte(now>>8))

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return nil, fmt.Errorf("alive request: %w", err)
	}

	if recv[0] == CodeNotification {
		u31Log.Info("Received Notification, retrying Alive Request")
		return d.SendAliveRequest()
	}

	info, err := ParseAliveResponse(recv)
	if err != nil {
		return nil, err
	}

	d.onlineTime = info.OnlineTime
	d.totalTime = info.TotalTime
	d.totalFlux = info.TotalFlux
	d.balance = info.Balance

	u31Log.Info("Keep alive succeeded",
		"onlineTime", fmt.Sprintf("%d s", info.OnlineTime),
		"usedTime", fmt.Sprintf("%d min", info.TotalTime),
		"usedFlux", fmt.Sprintf("%.2f MB", float64(info.TotalFlux)/1024.0),
		"balance", fmt.Sprintf("%.4f RMB", float64(info.Balance)/10000.0))

	return info, nil
}

// SendAlivePkt1 sends keep-alive misc packet 1 (step 0x01).
func (d *U31Dealer) SendAlivePkt1() error {
	return d.sendAlivePkt1(0)
}

func (d *U31Dealer) sendAlivePkt1(retryCount int) error {
	u31Log.Info("Send Alive Packet 1")

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
	// bytes 10-13: timestamp (0)
	// bytes 14-15: unknown (0)
	binary.LittleEndian.PutUint32(pkt[16:20], d.misc1Flux)
	// bytes 20-27: unknown (0)
	// bytes 28-31: client IP fixed 0.0.0.0
	// bytes 32-39: unknown (0)

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("alive pkt1: %w", err)
	}

	if recv[0] != CodeMisc {
		return fmt.Errorf("alive pkt1: unexpected code 0x%02x", recv[0])
	}

	if recv[5] == MiscFile {
		u31Log.Info("Received Misc File, retrying")
		copy(d.clientVersion[:], recv[6:8])
		if retryCount < 10 {
			return d.sendAlivePkt1(retryCount + 1)
		}
		return fmt.Errorf("alive pkt1: too many File retries")
	}

	u31Log.Info("Gateway returns: Response for Alive Packet 1")
	d.pktID++
	if len(recv) >= 20 {
		d.misc3Flux = binary.LittleEndian.Uint32(recv[16:20])
	}
	return nil
}

// SendAlivePkt2 sends keep-alive misc packet 2 (step 0x03).
func (d *U31Dealer) SendAlivePkt2() error {
	u31Log.Info("Send Alive Packet 2")

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
	// bytes 10-13: timestamp (0)
	// bytes 14-15: unknown (0)
	binary.LittleEndian.PutUint32(pkt[16:20], d.misc3Flux)
	// bytes 20-27: unknown (0)
	copy(pkt[28:32], d.localIP) // Client IP
	// bytes 32-39: unknown (0)

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("alive pkt2: %w", err)
	}

	if recv[0] != CodeMisc {
		return fmt.Errorf("alive pkt2: unexpected code 0x%02x", recv[0])
	}

	u31Log.Info("Gateway returns: Response for Alive Packet 2")
	d.pktID++
	if len(recv) >= 20 {
		d.misc1Flux = binary.LittleEndian.Uint32(recv[16:20])
	}
	return nil
}

// SendLogoutAuth sends the logout auth packet.
func (d *U31Dealer) SendLogoutAuth() error {
	if len(d.challenge) == 0 || len(d.authInfo) == 0 {
		return fmt.Errorf("not authenticated")
	}

	u31Log.Info("Send Logout Auth")

	pkt := d.buildLogoutPacket()

	recv, err := d.udp.SendWithRetry(pkt)
	if err != nil {
		return fmt.Errorf("logout auth: %w", err)
	}

	if recv[0] != CodeLoginSuccess {
		return fmt.Errorf("logout failed: code 0x%02x", recv[0])
	}

	u31Log.Info("Logged out")
	d.reset()
	return nil
}

// reset clears all session state.
func (d *U31Dealer) reset() {
	d.challenge = nil
	d.loginMD5A = nil
	d.authInfo = nil
	d.totalTime = 0
	d.totalFlux = 0
	d.balance = 0
	d.onlineTime = 0
	d.pktID = 0
	d.misc1Flux = 0
	d.misc3Flux = 0
}

// buildLoginPacket constructs the login/logout auth packet.
func (d *U31Dealer) buildLoginPacket(code byte) []byte {
	pkt := make([]byte, 0, 334)

	// Header: Code, Type, EOF, UserNameLength+20
	usernameLen := len(d.username)
	if usernameLen > 36 {
		usernameLen = 36
	}
	pkt = append(pkt, code, 0x01, 0x00, byte(usernameLen+20))

	// MD5A = MD5(code + type + challenge + password)
	md5aInput := []byte{code, 0x01}
	md5aInput = append(md5aInput, d.challenge...)
	md5aInput = append(md5aInput, d.password...)
	md5a := util.MD5Sum(md5aInput)
	d.loginMD5A = md5a[:]
	pkt = append(pkt, md5a[:]...)

	// Username (36 bytes, padded)
	usernameBlock := make([]byte, 36)
	copy(usernameBlock, d.username)
	pkt = append(pkt, usernameBlock...)

	// Config bytes
	pkt = append(pkt, 0x00, 0x00)

	// MAC XOR MD5A
	for i := 0; i < 6; i++ {
		pkt = append(pkt, d.localMAC[i]^md5a[i])
	}

	// MD5B = MD5(0x01 + password + challenge + 0x00*4)
	md5bInput := []byte{0x01}
	md5bInput = append(md5bInput, d.password...)
	md5bInput = append(md5bInput, d.challenge...)
	md5bInput = append(md5bInput, 0x00, 0x00, 0x00, 0x00)
	md5b := util.MD5Sum(md5bInput)
	pkt = append(pkt, md5b[:]...)

	// NIC count + IPs
	pkt = append(pkt, 0x01) // 1 NIC
	pkt = append(pkt, d.localIP...)
	pkt = append(pkt, make([]byte, 12)...) // 3 more NICs

	// Checksum1 = MD5(pkt_so_far + [0x14, 0x00, 0x07, 0x0b])
	checksumInput := make([]byte, len(pkt))
	copy(checksumInput, pkt)
	checksumInput = append(checksumInput, md5ChecksumTail...)
	checksum1 := util.MD5Sum(checksumInput)
	pkt = append(pkt, checksum1[:8]...) // only first 8 bytes

	// IP Dog + Fill
	pkt = append(pkt, 0x01)
	pkt = append(pkt, make([]byte, 4)...)

	// Hostname (32 bytes, padded)
	hostnameBlock := make([]byte, 32)
	copy(hostnameBlock, d.hostname)
	pkt = append(pkt, hostnameBlock...)

	// DNS + DHCP + DNS2 + Fill
	pkt = append(pkt, make([]byte, 4)...) // Primary DNS
	pkt = append(pkt, make([]byte, 4)...) // DHCP
	pkt = append(pkt, make([]byte, 4)...) // Secondary DNS
	pkt = append(pkt, make([]byte, 8)...) // Fill

	// OS info
	pkt = append(pkt, make([]byte, 4)...)     // Unknown1
	pkt = append(pkt, make([]byte, 4)...)     // OS major
	pkt = append(pkt, make([]byte, 4)...)     // OS minor
	pkt = append(pkt, make([]byte, 4)...)     // OS build
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x02) // Unknown2

	// Kernel version (32 bytes, padded)
	kvBlock := make([]byte, 32)
	copy(kvBlock, d.kernelVersion)
	pkt = append(pkt, kvBlock...)

	// Fill 96 bytes
	pkt = append(pkt, make([]byte, 96)...)

	// Checksum2 = [0x0a, 0x00, 0x02, 0x0c] + checksum1[10:14] + [0x00, 0x00]
	pkt = append(pkt, 0x0a, 0x00, 0x02, 0x0c)
	pkt = append(pkt, checksum1[10:14]...)
	pkt = append(pkt, 0x00, 0x00)

	// MAC
	pkt = append(pkt, d.localMAC[:6]...)

	// Auto_Logout, Multicast_Mode, Unknown
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)

	return pkt
}

// buildLogoutPacket constructs the logout auth packet (code 0x06).
func (d *U31Dealer) buildLogoutPacket() []byte {
	pkt := make([]byte, 0, 80)

	usernameLen := len(d.username)
	if usernameLen > 36 {
		usernameLen = 36
	}
	pkt = append(pkt, CodeLogoutAuth, 0x01, 0x00, byte(usernameLen+20))

	// MD5A with logout code
	md5aInput := []byte{CodeLogoutAuth, 0x01}
	md5aInput = append(md5aInput, d.challenge...)
	md5aInput = append(md5aInput, d.password...)
	md5a := util.MD5Sum(md5aInput)
	d.loginMD5A = md5a[:]
	pkt = append(pkt, md5a[:]...)

	// Username (36 bytes)
	usernameBlock := make([]byte, 36)
	copy(usernameBlock, d.username)
	pkt = append(pkt, usernameBlock...)

	// Config
	pkt = append(pkt, 0x00, 0x00)

	// MAC XOR MD5A
	for i := 0; i < 6; i++ {
		pkt = append(pkt, d.localMAC[i]^md5a[i])
	}

	// Auth info
	pkt = append(pkt, d.authInfo...)

	return pkt
}
