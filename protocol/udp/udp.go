package udp

import (
	"fmt"
	"net"
	"time"

	"github.com/vanishcode/drcom-go/util"
)

const (
	maxRetries = 2
	retryDelay = 2 * time.Second
	bufSize    = 2048
)

var log = util.NewLogger(util.SectionSYS)

// Dealer handles UDP communication with the DrCOM gateway.
type Dealer struct {
	conn    *net.UDPConn
	gateway *net.UDPAddr
	timeout time.Duration
}

// NewDealer creates a UDP dealer bound to localIP, targeting gatewayIP:port.
func NewDealer(gatewayIP string, gatewayPort int, localIP string, timeoutMs int) (*Dealer, error) {
	gw := &net.UDPAddr{
		IP:   net.ParseIP(gatewayIP),
		Port: gatewayPort,
	}

	local := &net.UDPAddr{
		IP:   net.ParseIP(localIP),
		Port: 0,
	}

	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return nil, fmt.Errorf("udp listen: %w", err)
	}

	return &Dealer{
		conn:    conn,
		gateway: gw,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
	}, nil
}

// Close closes the underlying UDP connection.
func (d *Dealer) Close() error {
	return d.conn.Close()
}

// Send sends data to the gateway and returns the response.
// It sets a read deadline based on the configured timeout.
func (d *Dealer) Send(data []byte) ([]byte, error) {
	_, err := d.conn.WriteToUDP(data, d.gateway)
	if err != nil {
		return nil, fmt.Errorf("udp send: %w", err)
	}

	d.conn.SetReadDeadline(time.Now().Add(d.timeout))

	var result []byte
	for {
		buf := make([]byte, bufSize)
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if len(result) > 0 {
					return result, nil
				}
				return nil, fmt.Errorf("udp recv: timeout")
			}
			return nil, fmt.Errorf("udp recv: %w", err)
		}
		result = append(result, buf[:n]...)
		if n < bufSize {
			break
		}
	}

	return result, nil
}

// SendWithRetry sends data and retries up to maxRetries on failure.
func (d *Dealer) SendWithRetry(data []byte) ([]byte, error) {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		resp, err := d.Send(data)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if i < maxRetries {
			log.Warn("UDP send failed, retrying", "attempt", i+1, "err", err)
			time.Sleep(retryDelay)
		}
	}
	return nil, fmt.Errorf("udp send failed after %d retries: %w", maxRetries, lastErr)
}
