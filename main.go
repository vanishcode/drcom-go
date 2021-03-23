package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket/pcap"
	"gopkg.in/ini.v1"
)

const (
	App     string = "DrCOM(P) Golang"
	Version string = "v0.1"
	Author  string = "by vanishcode"
	Date    string = "2021.3.23"
)

// DrcomConfig 配置，详见conf配置文件注释
type DrcomConfig struct {
	General struct {
		UserName   string
		PassWord   string
		Mode       int
		AutoOnline int
		AutoRedial int
	}
	Remote struct {
		IP           string
		Port         int
		UseBroadcast int
		MAC          string
	}
	Local struct {
		IP            string
		MAC           string
		NIC           string
		EAPTimeout    int
		UDPTimeout    int
		HostName      string
		KernelVersion string
	}
}

// 登录状态
var State int

const (
	OFFLINE_PROCESSING = 0
	OFFLINE_NOTIFY     = 1
	OFFLINE            = 2
	ONLINE_PROCESSING  = 3
	ONLINE             = 4
)

var (
	EthernetBroadcast  = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	EthernetNearestMac = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
)

func main() {
	// Link Start!
	fmt.Println("--------------------------------------------")
	fmt.Println(App, Version, Author, Date)
	fmt.Println("--------------------------------------------")

	var configFilePath string

	flag.StringVar(&configFilePath, "c", "drcom.conf", "默认为同目录drcom.conf文件")

	config := new(DrcomConfig)

	err := ini.MapTo(config, configFilePath)
	if err != nil {
		log.Println("打开配置文件失败")
		os.Exit(-1)
	}

	// ip和mac可以根据网卡名获取
	config.Local.IP = GetIpByNic(config.Local.NIC)
	config.Local.MAC = GetMacByNic(config.Local.NIC)

	pcap.Version()
	MakeEthernetHeader(config)

	State = OFFLINE_PROCESSING

	online(config)

}

func online(config *DrcomConfig) {
	State = ONLINE_PROCESSING

	PcapInit(config)

	if config.Remote.UseBroadcast == 1 {

		Logoff(EthernetNearestMac)
		Logoff(EthernetNearestMac)

		Start(EthernetBroadcast)
		ResponseIdentity(EthernetBroadcast)
		ResponseMd5Challenge(EthernetBroadcast)

	} else {

		mac := MacProcessor(config.Remote.MAC)

		Logoff(mac)
		Logoff(mac)

		Start(mac)
		ResponseIdentity(mac)
		ResponseMd5Challenge(mac)
	}

	keepalive(State)

}

func keepalive(state int) {
	if state != OFFLINE_PROCESSING {
		for {
			KeepAlivePacket1()
			KeepAlivePacket1()
			time.Sleep(time.Duration(20) * time.Second)

			state = ONLINE
		}
	}
}
