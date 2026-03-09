package config

import (
	"fmt"
	"net"
	"os"

	"github.com/vanishcode/drcom-go/util"
	"gopkg.in/yaml.v3"
)

// Config holds all settings for EasyDrcom.
type Config struct {
	General GeneralConfig `yaml:"general"`
	Remote  RemoteConfig  `yaml:"remote"`
	Local   LocalConfig   `yaml:"local"`
	Fake    FakeConfig    `yaml:"fake"`
}

type GeneralConfig struct {
	Mode       int    `yaml:"mode"`
	UserName   string `yaml:"username"`
	PassWord   string `yaml:"password"`
	AutoOnline bool   `yaml:"auto_online"`
	AutoRedial bool   `yaml:"auto_redial"`
}

type RemoteConfig struct {
	IP           string `yaml:"ip"`
	Port         int    `yaml:"port"`
	UseBroadcast bool   `yaml:"use_broadcast"`
	MACStr       string `yaml:"mac"`

	MAC net.HardwareAddr `yaml:"-"`
}

type LocalConfig struct {
	NIC           string `yaml:"nic"`
	HostName      string `yaml:"hostname"`
	KernelVersion string `yaml:"kernel_version"`
	EAPTimeout    int    `yaml:"eap_timeout"`
	UDPTimeout    int    `yaml:"udp_timeout"`

	IP  net.IP           `yaml:"-"`
	MAC net.HardwareAddr `yaml:"-"`
}

type FakeConfig struct {
	Enable   bool   `yaml:"enable"`
	MACStr   string `yaml:"mac"`
	UserName string `yaml:"username"`
	PassWord string `yaml:"password"`

	MAC net.HardwareAddr `yaml:"-"`
}

// LoadConfig reads a YAML config file and returns a Config with defaults applied.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	c := &Config{
		General: GeneralConfig{
			AutoOnline: true,
			AutoRedial: true,
		},
		Remote: RemoteConfig{
			IP:           "172.25.8.4",
			Port:         61440,
			UseBroadcast: true,
		},
		Local: LocalConfig{
			HostName:      "EasyDrcom for HITwh",
			KernelVersion: "v0.9",
			EAPTimeout:    1000,
			UDPTimeout:    2000,
		},
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	// Validate required fields
	if c.General.UserName == "" {
		return nil, fmt.Errorf("general.username is required")
	}
	if c.General.PassWord == "" {
		return nil, fmt.Errorf("general.password is required")
	}
	if c.Local.NIC == "" {
		return nil, fmt.Errorf("local.nic is required")
	}

	// Parse Remote MAC
	if !c.Remote.UseBroadcast {
		if c.Remote.MACStr == "" {
			c.Remote.MACStr = "00:1a:a9:c3:3a:59"
		}
		c.Remote.MAC, err = net.ParseMAC(c.Remote.MACStr)
		if err != nil {
			return nil, fmt.Errorf("remote.mac %q: %w", c.Remote.MACStr, err)
		}
	}

	// Parse Fake MAC
	if c.Fake.Enable {
		c.Fake.MAC, err = net.ParseMAC(c.Fake.MACStr)
		if err != nil {
			return nil, fmt.Errorf("fake.mac %q: %w", c.Fake.MACStr, err)
		}
		if c.Fake.UserName == "" {
			return nil, fmt.Errorf("fake.username is required when fake.enable is true")
		}
		if c.Fake.PassWord == "" {
			return nil, fmt.Errorf("fake.password is required when fake.enable is true")
		}
	}

	// Fetch NIC MAC and IP
	c.Local.MAC, c.Local.IP, err = util.GetNICAddrs(c.Local.NIC)
	if err != nil {
		return nil, fmt.Errorf("NIC info: %w", err)
	}

	return c, nil
}

// EffectiveMAC returns the MAC to use for DrCOM auth (fake if enabled).
func (c *Config) EffectiveMAC() net.HardwareAddr {
	if c.Fake.Enable {
		return c.Fake.MAC
	}
	return c.Local.MAC
}

// EffectiveUserName returns the username to use for auth (fake if enabled).
func (c *Config) EffectiveUserName() string {
	if c.Fake.Enable {
		return c.Fake.UserName
	}
	return c.General.UserName
}

// EffectivePassWord returns the password to use for auth (fake if enabled).
func (c *Config) EffectivePassWord() string {
	if c.Fake.Enable {
		return c.Fake.PassWord
	}
	return c.General.PassWord
}
