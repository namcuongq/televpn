package vpn

import (
	"net"
	"televpn/core"
	"televpn/network"

	"github.com/fasthttp/websocket"
)

type TeleVpnClient struct {
	config Config

	defaultDialerWS  *websocket.Dialer
	defaultDialerTCP net.Dialer
	urlServerWS      string
	mySocket         *websocket.Conn
	vpnNetwork       *net.IPNet

	key              []byte
	Whitelist        map[string]bool
	chanErrorConnect chan bool

	Tun2Socket func(core.CommTCPConn, *websocket.Conn, []byte)
	Socket2Tun func(*websocket.Conn, core.CommTCPConn, []byte)
}

type TeleVpnServer struct {
	config Config

	Users   map[string]User
	Clients Client

	Tun2Socket func(core.CommTCPConn, *websocket.Conn, []byte)
	Socket2Tun func(*websocket.Conn, core.CommTCPConn, []byte)
}

const (
	DEFAULT_PATH     = "/help"
	DEFAULT_PATH_VPN = "/talk"
)

func makeKey(u User) []byte {
	return []byte(network.GetMD5Hash(u.Password + u.Ipaddress))
}
