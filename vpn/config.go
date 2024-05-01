package vpn

import (
	"fmt"
	"strings"
	"televpn/proxy"

	"github.com/BurntSushi/toml"
)

func LoadConfig(path string) (proxy.Config, error) {
	var config proxy.Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return config, fmt.Errorf("could not load config: %v", err)
	}

	if config.TTL <= 0 {
		config.TTL = 20
	}

	if config.MTU <= 0 {
		config.MTU = 1500
	}

	config.Mode = strings.ToLower(config.Mode)
	if config.Mode == "" {
		config.Mode = "ws"
	}

	if config.Mode != "tcp" && config.Mode != "ws" {
		return config, fmt.Errorf("vpn server is not support mode %s", config.Mode)
	}

	if config.RedirectGateway == "" {
		config.RedirectGateway = "0.0.0.0/0"
	}

	if len(config.DNSServer) < 1 {
		config.DNSServer = []string{"1.1.1.1"}
	}

	return config, nil
}
