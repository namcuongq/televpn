package vpn

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server         string
	Address        string
	DefaultGateway string
	MTU            int
	TTL            int
	User           string
	Pass           string
	HostHeader     string
	Public         bool

	DNSServer []string

	Whitelist []string
	Blacklist []string

	Users []User

	SSL    bool
	SSLKey string
	SSLCrt string

	Auto string

	RedirectGateway string
}

type User struct {
	Username  string
	Password  string
	Ipaddress string
}

func LoadConfig(path string) (Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return config, fmt.Errorf("could not load config: %v", err)
	}

	if config.TTL <= 0 {
		config.TTL = 20
	}

	if config.MTU <= 0 {
		config.MTU = 1500
	}

	if config.RedirectGateway == "" {
		config.RedirectGateway = "0.0.0.0/0"
	}

	if len(config.DNSServer) < 1 {
		config.DNSServer = []string{"1.1.1.1"}
	}

	return config, nil
}
