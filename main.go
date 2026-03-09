package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vanishcode/drcom-go/config"
	"github.com/vanishcode/drcom-go/session"
	"github.com/vanishcode/drcom-go/util"
)

var log = util.NewLogger(util.SectionSYS)

func main() {
	configPath := flag.String("c", "config.yaml", "path to config file")
	flag.Parse()

	fmt.Println("[DrCOM-Go v0.9 - Go rewrite of EasyDrcom for HITwh]")
	fmt.Println()

	log.Info("Loading config", "path", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Error("Failed to load config", "err", err)
		os.Exit(1)
	}

	log.Info("Config loaded",
		"user", cfg.General.UserName,
		"mode", cfg.General.Mode,
		"nic", cfg.Local.NIC,
		"ip", cfg.Local.IP,
		"mac", cfg.Local.MAC)

	sess, err := session.New(cfg)
	if err != nil {
		log.Error("Failed to initialize session", "err", err)
		os.Exit(1)
	}
	defer sess.Close()

	log.Info("Initialization done")

	if cfg.General.AutoOnline {
		log.Info("Auto-connecting...")
		if err := sess.GoOnline(); err != nil {
			log.Error("Failed to go online", "err", err)
		}
	} else {
		fmt.Println("Enter 'online' to connect.")
	}

	fmt.Println("Commands: online, offline, quit, help")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		switch cmd {
		case "online":
			state := sess.GetState()
			switch state {
			case session.StateOnline:
				fmt.Println("Already online!")
			case session.StateOnlineProcessing:
				fmt.Println("Online processing...")
			case session.StateOfflineProcessing:
				fmt.Println("Offline processing...")
			case session.StateOffline:
				log.Info("Going online...")
				if err := sess.GoOnline(); err != nil {
					log.Error("Failed to go online", "err", err)
				}
			}

		case "offline":
			state := sess.GetState()
			switch state {
			case session.StateOffline:
				fmt.Println("Not online.")
			case session.StateOnlineProcessing:
				fmt.Println("Online processing, please wait...")
			case session.StateOfflineProcessing:
				fmt.Println("Already going offline...")
			case session.StateOnline:
				log.Info("Going offline...")
				if err := sess.GoOffline(); err != nil {
					log.Error("Failed to go offline", "err", err)
				}
			}

		case "quit":
			state := sess.GetState()
			if state == session.StateOnlineProcessing || state == session.StateOfflineProcessing {
				fmt.Println("Please wait for processing to finish.")
				continue
			}
			if state == session.StateOnline {
				log.Info("Going offline before quit...")
				sess.GoOffline()
			}
			fmt.Println("Bye!")
			return

		case "help":
			fmt.Println("DrCOM-Go v0.9 - Go rewrite of EasyDrcom for HITwh")
			fmt.Println("Commands:")
			fmt.Println("  online  - connect to network")
			fmt.Println("  offline - disconnect from network")
			fmt.Println("  quit    - exit program")
			fmt.Println("  help    - show this help")

		case "":
			// ignore empty input

		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}
