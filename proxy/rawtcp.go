package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"televpn/core"
	"televpn/log"
	"televpn/network"
	"time"
)

const (
	TCP_STATUS_401 = 1
	TCP_STATUS_200 = 2
	TCP_STATUS_500 = 3
)

type RawTCPServer struct {
	ln       net.Listener
	mapUsers map[string]User
	status   int
}

type RawTCPClient struct {
	ip         [4]byte
	serverName string
	server     string
	tlsConfig  *tls.Config
	dialer     *net.Dialer
}

func NewTCPClient(ipSrc, serverName, server string, tlsConfig *tls.Config, dialer *net.Dialer) (*ProxyClient, error) {
	var p RawTCPClient
	ip := net.ParseIP(ipSrc).To4()
	p.ip = [4]byte{ip[0], ip[1], ip[2], ip[3]}
	p.serverName = serverName
	p.server = server
	p.tlsConfig = tlsConfig
	p.dialer = dialer
	return &ProxyClient{
		Forward: p.Forward,
	}, nil
}

func (p RawTCPClient) Forward(src core.CommTCPConn, key, sessionKey []byte) error {
	defer src.Close()
	addr, _ := net.ResolveTCPAddr("tcp", src.LocalAddr().String())
	var port [2]int
	port[0], port[1] = addr.Port>>8, addr.Port&255

	//	-------------------------------------------
	//
	// | 4 byte |  48 byte  |  16 byte  |  2 byte  |
	//
	//	-------------------------------------------
	//	  Ipv4    Authen Key   IP Dest    Port Dest

	var header = make([]byte, 4+48+16+2)
	header = append(p.ip[:], sessionKey[:]...)
	header = append(header, addr.IP.To16()[:]...)
	header = append(header, byte(port[0]))
	header = append(header, byte(port[1]))

	dest, err := tls.DialWithDialer(p.dialer, "tcp", p.server, p.tlsConfig)
	if err != nil {
		log.Trace(err)
		return err
	}
	defer dest.Close()

	err = dest.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return err
	}
	_, err = dest.Write(header)
	if err != nil {
		return err
	}
	err = src.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}

	flag := make([]byte, 1)
	err = network.ReadFull(dest, flag, 5*time.Second)
	if err != nil {
		return err
	}

	switch flag[0] {
	case TCP_STATUS_200:
		go func() {
			network.SendEn(dest, src, key)
			src.Close()
			dest.Close()
		}()
		network.ReadDe(src, dest, key)
	case TCP_STATUS_401:
		log.Trace("Authen failed!")
		return fmt.Errorf("Authen failed!")
	case TCP_STATUS_500:
		log.Trace("VPN server is paused!")
		return fmt.Errorf("VPN server is paused!")
	}

	return nil
}

func NewTCPServer(config Config) (*ProxyServer, error) {
	var s RawTCPServer
	cer, err := tls.LoadX509KeyPair(config.SSLCrt, config.SSLKey)
	if err != nil {
		return nil, err
	}

	//setup authen
	s.mapUsers = make(map[string]User, len(config.Users))
	for _, u := range config.Users {
		s.mapUsers[u.Ipaddress] = u
	}

	configTLS := &tls.Config{Certificates: []tls.Certificate{cer}}
	s.ln, err = tls.Listen("tcp", config.Server, configTLS)
	if err != nil {
		return nil, err
	}

	s.status = TCP_STATUS_200

	return &ProxyServer{
		Stop:   s.stop,
		Pause:  s.pause,
		Resume: s.resume,
		Handle: s.handle,
	}, nil
}

func (s *RawTCPServer) pause() {
	s.status = TCP_STATUS_500
}

func (s *RawTCPServer) resume() {
	s.status = TCP_STATUS_200
}

func (s *RawTCPServer) stop() {
	s.ln.Close()
}

//	-------------------------------------------
//
// | 4 byte |  48 byte  |  16 byte  |  2 byte  |
//
//	-------------------------------------------
//	  Ipv4    Authen Key   IP Dest    Port Dest

func (s *RawTCPServer) handle() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(conn)
	}
	return nil
}

func (s *RawTCPServer) handleConnection(src net.Conn) {
	defer src.Close()
	headerLen := 4 + 48 + 16 + 2
	var headerByte = make([]byte, headerLen)

	err := network.ReadFull(src, headerByte, 5*time.Second)
	if err != nil {
		return
	}

	ipSrc := headerByte[:4]
	authen := headerByte[4 : 4+48]
	ipDest := headerByte[4+48 : 4+48+16]
	portDestB := headerByte[4+48+16:]
	portDest := int(portDestB[0])<<8 + int(portDestB[1])

	// 1: authen failed
	// 2: success
	// 3: pause
	u, found := s.mapUsers[net.IP(ipSrc).String()]
	if !found {
		s.sendAuthenFailed(src)
		return
	}

	key, err := network.AESDecrypt([]byte(network.GetMD5Hash(u.Username+u.Password)), authen)
	if err != nil {
		s.sendAuthenFailed(src)
		return
	}

	s.sendAuthenOk(src)
	dst, err := net.Dial("tcp", fmt.Sprintf("%s:%d", net.IP(ipDest).String(), portDest))
	if err != nil {
		return
	}
	defer dst.Close()

	go func() {
		network.ReadDe(dst, src, key)
		src.Close()
		dst.Close()
	}()

	network.SendEn(src, dst, key)
}

func (s *RawTCPServer) sendAuthenFailed(src net.Conn) error {
	err := src.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return err
	}
	_, err = src.Write([]byte{TCP_STATUS_401})
	if err != nil {
		return err
	}
	return src.SetWriteDeadline(time.Time{})
}

func (s *RawTCPServer) sendAuthenOk(src net.Conn) error {
	err := src.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return err
	}
	_, err = src.Write([]byte{byte(s.status)})
	if err != nil {
		return err
	}
	return src.SetWriteDeadline(time.Time{})
}
