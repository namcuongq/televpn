package vpn

import (
	"net"
	"televpn/network"
	"televpn/proxy"
)

type TeleVpnClient struct {
	config proxy.Config

	defaultDialerTCP net.Dialer
	defaultDialerUDP net.Dialer
	vpnNetwork       *net.IPNet
	proxyClient      *proxy.ProxyClient

	key              []byte
	Whitelist        map[string]bool
	chanErrorConnect chan bool
}

type TeleVpnServer struct {
	config proxy.Config
	s      *proxy.ProxyServer
	// Clients Client
}

func makeKey(u proxy.User) []byte {
	return []byte(network.GetMD5Hash(u.Username + u.Password))
}
