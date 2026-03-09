package util

import (
	"fmt"
	"net"
)

// GetNICAddrs returns the MAC address and IPv4 address of the named network interface.
func GetNICAddrs(name string) (mac net.HardwareAddr, ip net.IP, err error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %q: %w", name, err)
	}

	mac = iface.HardwareAddr
	if len(mac) == 0 {
		return nil, nil, fmt.Errorf("interface %q: no MAC address", name)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("interface %q addrs: %w", name, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			ip = v4
			break
		}
	}

	if ip == nil {
		return nil, nil, fmt.Errorf("interface %q: no IPv4 address", name)
	}

	return mac, ip, nil
}
