package main

import (
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

func Start(mac []byte) {

}

func Logoff(config *DrcomConfig, mac []byte) {
	log.Println("Start Logoff...")

	empty := []byte{}
	eapolLogoff := []byte{
		0x01,
		0x02,
		0x00, 0x00,
	}

	handle, err := pcap.OpenLive(config.Local.NIC, SnapLen, true, time.Duration(config.Local.EAPTimeout))
	defer handle.Close()

	if err != nil {
		log.Fatalln(err, "libpcap异常")
	}

	ethHeader := MakeEthernetHeader(config)
	withEthHeader := append(empty, ethHeader.Contents...)
	data := append(withEthHeader, eapolLogoff...)

	err = handle.WritePacketData(data)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Logoff success")
}

func ResponseIdentity(mac []byte) {

}

func ResponseMd5Challenge(mac []byte) {

}
