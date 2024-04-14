package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"televpn/core"
	"televpn/log"
	"televpn/network"

	"github.com/fasthttp/websocket"
)

type WSServer struct {
	ln *http.Server

	mapUsers map[string]User
	status   int
	sslCrt   string
	sslKey   string
}

type WSClient struct {
	ip         string
	serverName string
	server     string
	tlsConfig  *tls.Config
	dialer     *websocket.Dialer
}

type slashFix struct {
	mux http.Handler
}

func (h *slashFix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	h.mux.ServeHTTP(w, r)
}

func NewWSClient(ipSrc, serverName, server string, tlsConfig *tls.Config, dialer *net.Dialer) (*ProxyClient, error) {
	var p WSClient
	p.ip = ipSrc
	p.serverName = serverName
	p.server = server
	p.tlsConfig = tlsConfig

	p.dialer = websocket.DefaultDialer
	p.dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.Dial(network, addr)
		return conn, err
	}
	p.dialer.TLSClientConfig = tlsConfig

	return &ProxyClient{
		Forward: p.Forward,
	}, nil
}

func (p WSClient) Forward(src core.CommTCPConn, sessionKey []byte) error {
	defer src.Close()
	connSocket, resp, err := p.dialer.Dial(
		"wss://"+p.server+"/start1.html",
		http.Header{
			"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"},
			"X-Forwarded-For": []string{p.ip},
			"X-Id":            []string{base64.URLEncoding.EncodeToString(sessionKey)},
			"Via":             []string{src.LocalAddr().String()},
		})
	if err != nil {
		log.Trace(err)
		return err
	}
	defer connSocket.Close()

	switch resp.StatusCode {
	case http.StatusSwitchingProtocols:
		go func() {
			io.Copy(connSocket.NetConn(), src)
			connSocket.Close()
			src.Close()
		}()

		io.Copy(src, connSocket.NetConn())
	case http.StatusUnauthorized:
		log.Trace("Authen failed!")
		return fmt.Errorf("Authen failed!")
	case http.StatusInternalServerError:
		log.Trace("VPN server is paused!")
		return fmt.Errorf("VPN server is paused!")
	}

	return nil
}

func NewWSServer(config Config) (*ProxyServer, error) {
	var upgrader = websocket.Upgrader{}
	httpMux := http.NewServeMux()
	var s WSServer

	//setup authen
	s.mapUsers = make(map[string]User, len(config.Users))
	for _, u := range config.Users {
		s.mapUsers[u.Ipaddress] = u
	}

	httpMux.HandleFunc("/start1.html", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-Forwarded-For")
		authenData := r.Header.Get("X-Id")
		destIp := r.Header.Get("Via")

		if len(clientIP) < 1 || len(authenData) < 1 || len(destIp) < 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		u, found := s.mapUsers[clientIP]
		if !found {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenByte, err := base64.URLEncoding.DecodeString(authenData)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, err = network.AESDecrypt([]byte(network.GetMD5Hash(u.Username+u.Password)), tokenByte)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if s.status == TCP_STATUS_500 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Println("aaaaaaaaaa")
		currentConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer currentConn.Close()

		remoteConn, err := net.Dial("tcp", destIp)
		if err != nil {
			return
		}
		defer remoteConn.Close()

		go func() {
			io.Copy(currentConn.NetConn(), remoteConn)
			currentConn.Close()
			remoteConn.Close()
		}()

		io.Copy(remoteConn, currentConn.NetConn())
	})

	s.ln = &http.Server{Addr: config.Server, Handler: &slashFix{httpMux}, ErrorLog: nil}
	s.sslCrt = config.SSLCrt
	s.sslKey = config.SSLKey

	return &ProxyServer{
		Stop:   s.stop,
		Pause:  s.pause,
		Resume: s.resume,
		Handle: s.handle,
	}, nil
}

func (s *WSServer) pause() {
	s.status = TCP_STATUS_500
}

func (s *WSServer) resume() {
	s.status = TCP_STATUS_200
}

func (s *WSServer) stop() {
	s.ln.Close()
}

func (s *WSServer) handle() error {
	return s.ln.ListenAndServeTLS(s.sslCrt, s.sslKey)
}
