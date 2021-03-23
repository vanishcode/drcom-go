package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SnapLen l
var SnapLen int32 = 1518

func PcapInit(config *DrcomConfig) *pcap.Handle {
	handle, err := pcap.OpenLive(config.Local.NIC, SnapLen, true, time.Duration(config.Local.EAPTimeout))
	defer handle.Close()

	if err != nil {
		log.Fatalln(err, "libpcap异常")
	}

	list, _ := handle.ListDataLinks()
	if list[0].Name != "EN10MB" {
		log.Fatalln(err, "网卡异常")
	}

	handle.SetBPFFilter("ether dst " + config.Local.MAC + " and ether proto 0x888e")

	return handle
}

// MakeEthernetHeader h
func MakeEthernetHeader(config *DrcomConfig) *layers.Ethernet {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(MacProcessor(config.Local.MAC)),
		DstMAC:       net.HardwareAddr(MacProcessor(config.Remote.MAC)),
		EthernetType: 0x888e, // 802.1x
	}

	return ethernetLayer
}
