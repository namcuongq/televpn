package vpn

import (
	loggo "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"televpn/core"
	"televpn/log"
	"televpn/network"

	"github.com/fasthttp/websocket"
)

type TeleVpnClient struct {
	config Config

	defaultDialerWS  *websocket.Dialer
	defaultDialerTCP net.Dialer
	urlServerWS      string
	vpnNetwork       *net.IPNet
	publicWS         PublicWebSocket

	key              []byte
	Whitelist        map[string]bool
	chanErrorConnect chan bool

	Tun2Socket func(core.CommTCPConn, *websocket.Conn, []byte)
	Socket2Tun func(*websocket.Conn, core.CommTCPConn, []byte)
}

type PublicWebSocket struct {
	mu       sync.Mutex
	mySocket *websocket.Conn
}

func NewPublicWebSocket(c *websocket.Conn) PublicWebSocket {
	return PublicWebSocket{mySocket: c}
}

func (p *PublicWebSocket) Send(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mySocket.WriteMessage(websocket.BinaryMessage, b)
}

type Client struct {
	mu   sync.Mutex
	data map[string]*websocket.Conn
}

func (c *Client) AddNill(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[ip] = nil
}

func (c *Client) Set(ip string, conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[ip] = conn
}

func (c *Client) Get(ip string) (*websocket.Conn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, found := c.data[ip]
	return conn, found
}

type TeleVpnServer struct {
	config Config

	Users      map[string]User
	Clients    Client
	httpMux    *http.ServeMux
	httpServer *http.Server

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

type httpLogWriter struct{}

func (*httpLogWriter) Write(p []byte) (int, error) {
	m := string(p)
	if strings.HasPrefix(m, "http: TLS handshake error") {
		log.Trace(m)
	} else {
		log.Debug(m)
	}
	return len(p), nil
}

func httpLogger() *loggo.Logger {
	return loggo.New(&httpLogWriter{}, "", 0)
}
