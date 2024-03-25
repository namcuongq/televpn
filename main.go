package main

import (
	"flag"
	"runtime"
	"televpn/vpn"

	"televpn/log"
)

var (
	configPath string
	logLevel   int
	ServerMode bool
)

const (
	VERSION = "1.0.1"
	RELEASE = "(26/03/2024)"
)

func main() {
	flag.Parse()
	config, err := vpn.LoadConfig(configPath)
	if err != nil {
		log.Error(err)
		return
	}

	log.SetLevel(logLevel)
	log.Info("Version:", VERSION, "-", RELEASE)
	if ServerMode {
		log.Info("VPN Server started successfully!")
		err = vpn.StartServer(config)
		if err != nil {
			log.Error(err)
		}
		return
	}

	log.Info("VPN Client started successfully!")
	err = vpn.StartClient(config)
	if err != nil {
		log.Error(err)
	}
}

func init() {
	flag.StringVar(&configPath, "config", "config.toml", "location of the config file")
	flag.BoolVar(&ServerMode, "S", false, "server mode")
	flag.IntVar(&logLevel, "l", log.LevelInfo, "log level: [1-DEBUG 2-INFO 3-ERROR]")
	runtime.GOMAXPROCS(runtime.NumCPU())
}
