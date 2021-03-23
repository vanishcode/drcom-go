package main

import (
	"encoding/hex"
	"log"
	"net"
	"strings"
)

// GetMacByNic 根据网卡名获取硬件地址（mac地址）
func GetMacByNic(nic string) string {
	var mac = ""
	inter, err := net.InterfaceByName(nic)

	if err != nil {
		log.Fatalln(err)
	}

	mac = inter.HardwareAddr.String()

	// fmt.Println(mac)

	return mac
}

// GetIpByNic 根据网卡名获取ip
func GetIpByNic(nic string) string {
	var ip = ""

	inter, err := net.InterfaceByName(nic)

	if err != nil {
		log.Fatalln(err)
	}

	addrs, _ := inter.Addrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}

	// fmt.Println(ip)

	return ip
}

// MacProcessor f
func MacProcessor(mac string) []byte {
	after, err := hex.DecodeString(strings.Join(strings.Split(mac, ":"), ""))

	if err != nil {
		log.Fatalln("mac地址不正确")
	}

	return after
}
