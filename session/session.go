package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vanishcode/drcom-go/config"
	"github.com/vanishcode/drcom-go/protocol/drcom"
	"github.com/vanishcode/drcom-go/protocol/eap"
	"github.com/vanishcode/drcom-go/util"
)

const keepAliveInterval = 20 * time.Second

var (
	broadcastMAC = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	nearestMAC   = []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
)

var log = util.NewLogger(util.SectionSYS)

// State represents the session state.
type State int

const (
	StateOffline State = iota
	StateOnlineProcessing
	StateOnline
	StateOfflineProcessing
)

func (s State) String() string {
	switch s {
	case StateOffline:
		return "OFFLINE"
	case StateOnlineProcessing:
		return "ONLINE_PROCESSING"
	case StateOnline:
		return "ONLINE"
	case StateOfflineProcessing:
		return "OFFLINE_PROCESSING"
	default:
		return "UNKNOWN"
	}
}

// Session manages the authentication lifecycle.
type Session struct {
	cfg *config.Config
	eap *eap.Dealer
	u31 *drcom.U31Dealer
	u62 *drcom.U62Dealer

	mu     sync.Mutex
	state  State
	cancel context.CancelFunc // cancels the online goroutine
	done   chan struct{}      // closed when online goroutine exits
}

// New creates a new Session from the given config.
func New(cfg *config.Config) (*Session, error) {
	eapDealer, err := eap.NewDealer(
		cfg.Local.NIC, cfg.Local.MAC, cfg.Local.IP,
		cfg.General.UserName, cfg.General.PassWord,
		cfg.Local.EAPTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("eap dealer: %w", err)
	}

	s := &Session{
		cfg:   cfg,
		eap:   eapDealer,
		state: StateOffline,
	}

	mac := cfg.EffectiveMAC()
	username := cfg.EffectiveUserName()
	password := cfg.EffectivePassWord()

	if cfg.General.Mode <= 1 {
		u31, err := drcom.NewU31Dealer(mac, cfg.Local.IP, username, password,
			cfg.Remote.IP, cfg.Remote.Port,
			cfg.Local.HostName, cfg.Local.KernelVersion,
			cfg.Local.UDPTimeout)
		if err != nil {
			eapDealer.Close()
			return nil, fmt.Errorf("u31 dealer: %w", err)
		}
		s.u31 = u31
	} else {
		u62, err := drcom.NewU62Dealer(mac, cfg.Local.IP,
			cfg.Remote.IP, cfg.Remote.Port,
			cfg.Local.UDPTimeout)
		if err != nil {
			eapDealer.Close()
			return nil, fmt.Errorf("u62 dealer: %w", err)
		}
		s.u62 = u62
	}

	return s, nil
}

// Close releases all resources.
func (s *Session) Close() {
	s.eap.Close()
	if s.u31 != nil {
		s.u31.Close()
	}
	if s.u62 != nil {
		s.u62.Close()
	}
}

// State returns the current session state.
func (s *Session) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) setState(st State) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

// gatewayMAC returns the MAC to use for EAP frames.
func (s *Session) gatewayMAC() []byte {
	if s.cfg.Remote.UseBroadcast {
		return broadcastMAC
	}
	return s.cfg.Remote.MAC
}

// GoOnline starts the authentication process in a goroutine.
// Returns an error if already online or processing.
func (s *Session) GoOnline() error {
	s.mu.Lock()
	if s.state != StateOffline {
		st := s.state
		s.mu.Unlock()
		return fmt.Errorf("cannot go online from state %s", st)
	}
	s.state = StateOnlineProcessing
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.onlineLoop(ctx)
	return nil
}

// GoOffline initiates the offline process and blocks until complete.
func (s *Session) GoOffline() error {
	s.mu.Lock()
	if s.state != StateOnline && s.state != StateOnlineProcessing {
		st := s.state
		s.mu.Unlock()
		return fmt.Errorf("cannot go offline from state %s", st)
	}
	s.state = StateOfflineProcessing
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()

	cancel()
	<-done // wait for online goroutine to exit

	s.performOffline()
	s.setState(StateOffline)
	log.Info("Offline")
	return nil
}

// onlineLoop is the main authentication and keep-alive loop.
func (s *Session) onlineLoop(ctx context.Context) {
	defer close(s.done)

	for {
		err := s.performOnline(ctx)
		if err != nil {
			log.Error("Go online failed", "err", err)
		}

		// Check if we were asked to go offline
		if ctx.Err() != nil {
			return
		}

		if !s.cfg.General.AutoRedial {
			s.setState(StateOffline)
			return
		}

		log.Info("Connection broken, retrying in 5 seconds")
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// performOnline runs a single online attempt: EAP + DrCOM login + keep-alive.
func (s *Session) performOnline(ctx context.Context) error {
	gwMAC := s.gatewayMAC()

	// EAP authentication (mode != 1 means dormitory, needs EAP)
	if s.cfg.General.Mode != 1 {
		// Send logoff first to clear stale state
		if s.cfg.Remote.UseBroadcast {
			s.eap.Logoff(nearestMAC)
			s.eap.Logoff(nearestMAC)
		} else {
			s.eap.Logoff(s.cfg.Remote.MAC)
			s.eap.Logoff(s.cfg.Remote.MAC)
		}

		if err := s.eap.Start(gwMAC); err != nil {
			return fmt.Errorf("eap start: %w", err)
		}
		if err := s.eap.ResponseIdentity(gwMAC); err != nil {
			return fmt.Errorf("eap identity: %w", err)
		}
		if err := s.eap.ResponseMD5Challenge(gwMAC); err != nil {
			return fmt.Errorf("eap md5: %w", err)
		}
	}

	// DrCOM login
	if s.cfg.General.Mode <= 1 {
		if err := s.u31.StartRequest(); err != nil {
			return fmt.Errorf("drcom start: %w", err)
		}
		if _, err := s.u31.SendLoginAuth(); err != nil {
			return fmt.Errorf("drcom login: %w", err)
		}
	}

	// Keep-alive loop
	return s.keepAliveLoop(ctx)
}

// keepAliveLoop runs the periodic keep-alive packets.
func (s *Session) keepAliveLoop(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		var err error
		if s.cfg.General.Mode <= 1 {
			if _, err = s.u31.SendAliveRequest(); err != nil {
				return fmt.Errorf("alive request: %w", err)
			}
			if err = s.u31.SendAlivePkt1(); err != nil {
				return fmt.Errorf("alive pkt1: %w", err)
			}
			if err = s.u31.SendAlivePkt2(); err != nil {
				return fmt.Errorf("alive pkt2: %w", err)
			}
		} else {
			if err = s.u62.SendAlivePkt1(); err != nil {
				return fmt.Errorf("alive pkt1: %w", err)
			}
			if err = s.u62.SendAlivePkt2(); err != nil {
				return fmt.Errorf("alive pkt2: %w", err)
			}
		}

		s.setState(StateOnline)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(keepAliveInterval):
		}
	}
}

// performOffline sends logout packets.
func (s *Session) performOffline() {
	if s.cfg.General.Mode <= 1 && s.u31 != nil {
		s.u31.SendAliveRequest()
		s.u31.StartRequest()
		s.u31.SendLogoutAuth()
	}

	// EAP logoff for dormitory modes (0 and 2)
	if s.cfg.General.Mode == 0 || s.cfg.General.Mode == 2 {
		if s.cfg.Remote.UseBroadcast {
			s.eap.Logoff(broadcastMAC)
			s.eap.Logoff(nearestMAC)
		} else {
			s.eap.Logoff(s.cfg.Remote.MAC)
		}
	}
}
