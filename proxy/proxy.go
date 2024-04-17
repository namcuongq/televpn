package proxy

import (
	"televpn/core"
)

type Config struct {
	Server         string
	Mode           string
	Address        string
	DefaultGateway string
	MTU            int
	TTL            int
	User           string
	Pass           string
	HostHeader     string
	Public         bool
	SkipVerify     bool

	DNSServer []string

	Whitelist []string
	Blacklist []string

	Users []User

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

type ProxyServer struct {
	Stop   func()
	Pause  func()
	Resume func()

	Handle func() error
}

type ProxyClient struct {
	Forward func(core.CommTCPConn, []byte, []byte) error
}
