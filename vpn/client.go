package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"televpn/core"
	"televpn/log"
	"televpn/network"
	"televpn/tun"
	"time"

	"github.com/fasthttp/websocket"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func StartClient(c Config) error {
	var vpn TeleVpnClient
	vpn.config = c
	var tunConfig = tun.Config{
		Name: "tun0",
		MTU:  c.MTU,
		Addr: c.Address,
		GW:   c.DefaultGateway,
		DNS:  c.DNSServer,
	}

	if !vpn.config.SSL {
		vpn.config.Public = false
	}

	dev, err := tun.NewTun(tunConfig)
	if err != nil {
		return fmt.Errorf("create tun error: %v", err)
	}

	currentGw, err := dev.GetDefaultGateway()
	if err != nil {
		return fmt.Errorf("get default gateway err: %v", err)
	}

	err = vpn.setupDialer(currentGw.Interface)
	if err != nil {
		return fmt.Errorf("setup dialer err: %v", err)
	}

	err = dev.RouteTraffic(tunConfig.Name, c.RedirectGateway, tunConfig.Addr)
	if err != nil {
		return fmt.Errorf("route traffic err: %v", err)
	}

	_, vpn.vpnNetwork, _ = net.ParseCIDR(vpn.config.Address + "/24")

	vpn.setupAuthen()
	vpn.handleExit()
	err = vpn.setupWhiteList()
	if err != nil {
		return fmt.Errorf("setup whitelist err: %v", err)
	}

	schema := "ws://"
	if vpn.config.SSL {
		schema = "wss://"
	}

	vpn.urlServerWS = schema + vpn.config.Server
	go vpn.reconnectPublic(dev)
	err = vpn.setupPublic(dev)
	if err != nil {
		return fmt.Errorf("setup public err: %v", err)
	}
	vpn.setProxyFunc()

	return vpn.forwardTransportFromIo(dev, tunConfig.MTU, vpn.rawTcpForwarder, vpn.rawUdpForwarder)
}

func (t *TeleVpnClient) handleExit() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		t.shutdown()
	}()
}

func (t *TeleVpnClient) shutdown() {
	os.Exit(1)
}

func (t *TeleVpnClient) setProxyFunc() {
	if t.config.SSL { //ssl don't need encrypt body
		t.Tun2Socket = func(ct core.CommTCPConn, c *websocket.Conn, b []byte) {
			network.Tun2Socket(ct, c)
		}
		t.Socket2Tun = func(c *websocket.Conn, ct core.CommTCPConn, b []byte) {
			network.Socket2Tun(c, ct)
		}
	} else {
		t.Tun2Socket = network.Tun2SocketWithEn
		t.Socket2Tun = network.Socket2TunWithEn
	}
}

func (t *TeleVpnClient) reconnectPublic(dev *tun.DevReadWriteCloser) {
	if t.config.Public {
		t.chanErrorConnect = make(chan bool, 1)
		var err error
		for {
			<-t.chanErrorConnect
			for i := 0; i < 3; i++ {
				time.Sleep(10 * time.Second)
				log.Info("try reconnect server", i+1, "...")
				err = t.setupPublic(dev)
				if err == nil {
					break
				}
				log.Error("error reconnect server", i+1, err)
			}
			if err != nil {
				log.Info("Shutdown vpn!")
				t.shutdown()
			}
			log.Info("Connect server successful!")
		}
	}
}

func (t *TeleVpnClient) setupPublic(dev *tun.DevReadWriteCloser) error {
	if t.config.Public {
		tmpKey := network.UUID()
		authenData, err := network.AESEncrypt(t.key, []byte(tmpKey+":"+t.config.Address))
		if err != nil {
			return err
		}

		conn, err := network.ConnectWebSocket(t.defaultDialerWS,
			t.urlServerWS+DEFAULT_PATH_VPN,
			t.config.HostHeader, t.config.User, authenData)
		if err != nil {
			log.Error(err)
			return err
		}

		t.publicWS = NewPublicWebSocket(conn)

		go func() {
			for {
				_, message, err := conn.ReadMessage()
				if err != nil {
					break
				}

				_, err = dev.Write(message)
				if err != nil {
					break
				}
			}
		}()

		go func() {
			ticker := time.NewTicker(time.Duration(t.config.TTL) * time.Second)
			defer func() {
				conn.Close()
				ticker.Stop()
			}()

			for {
				select {
				case <-ticker.C:
					log.Trace("send ping", conn.RemoteAddr())
					err := t.publicWS.Send([]byte("ping"))
					if err != nil {
						log.Error("send ping error", err)
						t.chanErrorConnect <- true
						return
					}
				}
			}
		}()
	}

	return nil
}

func (t *TeleVpnClient) setupWhiteList() error {
	t.Whitelist = make(map[string]bool)
	for _, ip := range t.config.Whitelist {
		if !strings.Contains(ip, "/") {
			t.Whitelist[ip] = true
			continue
		} else if strings.HasSuffix(ip, "/32") {
			t.Whitelist[strings.Replace(ip, "/32", "", 1)] = true
			continue
		}
		hosts, err := network.Hosts(ip)
		if err != nil {
			return err
		}
		for _, host := range hosts {
			t.Whitelist[host] = true
		}
	}

	return nil
}

func (t *TeleVpnClient) setupAuthen() {
	t.key = makeKey(User{Username: t.config.User, Password: t.config.Pass, Ipaddress: t.config.Address})
}

func (t *TeleVpnClient) setupDialer(ip string) error {
	var tlsConfig *tls.Config
	if t.config.SSL {
		caCert, err := ioutil.ReadFile(t.config.SSLCrt)
		if err != nil {
			return fmt.Errorf("Error opening cert file "+t.config.SSLCrt+", error:", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig = &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}

	} else {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	addrTCP, err := net.ResolveTCPAddr("tcp", ip+":0")
	if err != nil {
		return err
	}

	addrUDP, err := net.ResolveUDPAddr("udp", ip+":0")
	if err != nil {
		return err
	}

	t.defaultDialerTCP = net.Dialer{LocalAddr: addrTCP, Timeout: 5 * time.Second}
	t.defaultDialerUDP = net.Dialer{LocalAddr: addrUDP, Timeout: 5 * time.Second}
	dialer := &t.defaultDialerTCP

	t.defaultDialerWS = websocket.DefaultDialer
	t.defaultDialerWS.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.Dial(network, addr)
		return conn, err
	}
	t.defaultDialerWS.TLSClientConfig = tlsConfig
	return nil
}

func (t *TeleVpnClient) rawTcpForwarder(conn core.CommTCPConn) error {
	defer conn.Close()
	destIP := network.GetIp(conn.LocalAddr().String())
	_, found := t.Whitelist[destIP]
	if found {
		remoteConn, err := t.defaultDialerTCP.Dial("tcp", conn.LocalAddr().String())
		if err != nil {
			return err
		}
		defer remoteConn.Close()
		go io.Copy(remoteConn, conn)
		io.Copy(conn, remoteConn)
		return nil
	}

	tmpKey := network.UUID()
	tmpKeyByte := []byte(tmpKey)
	authenData, err := network.AESEncrypt(t.key, []byte(tmpKey+":"+conn.LocalAddr().String()))
	if err != nil {
		return err
	}

	connSocket, err := network.ConnectWebSocket(t.defaultDialerWS,
		t.urlServerWS+DEFAULT_PATH,
		t.config.HostHeader, t.config.User, authenData)
	if err != nil {
		log.Debug(err)
		return err
	}
	defer connSocket.Close()

	go t.Tun2Socket(conn, connSocket, tmpKeyByte)
	t.Socket2Tun(connSocket, conn, tmpKeyByte)
	return nil
}

func (t *TeleVpnClient) rawUdpForwarder(conn core.CommUDPConn, ep core.CommEndpoint) error {
	defer conn.Close()
	remoteConn, err := t.defaultDialerUDP.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		return err
	}
	defer remoteConn.Close()

	go io.Copy(remoteConn, conn)
	io.Copy(conn, remoteConn)
	return nil
}

func (t *TeleVpnClient) forwardTransportFromIo(dev io.ReadWriteCloser, mtu int, tcpCallback core.ForwarderCall, udpCallback core.UdpForwarderCall) error {
	_, channelLinkID, err := core.NewDefaultStack(mtu, tcpCallback, udpCallback)
	if err != nil {
		log.Error("New Stack error:", err)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(_ctx context.Context) {
		for {
			info := channelLinkID.ReadContext(_ctx)
			if info.IsNil() {
				log.Error("channelLinkID exit")
				break
			}
			info.ToView().WriteTo(dev)
			info.DecRef()
		}
	}(ctx)

	var buf = make([]byte, mtu+80)
	var recvLen = 0
	for {
		recvLen, err = dev.Read(buf[:])
		if err != nil {
			log.Error("error read dev: %v", err)
			break
		}

		packetHeader := network.ParseHeaderPacket(buf[:recvLen])
		if t.config.Public && t.vpnNetwork.Contains(packetHeader.IPDst) {
			t.publicWS.Send(buf[:recvLen])
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf[:recvLen]),
		})

		if packetHeader.IsIPv6 {
			channelLinkID.InjectInbound(header.IPv6ProtocolNumber, pkt)
		} else {
			channelLinkID.InjectInbound(header.IPv4ProtocolNumber, pkt)
		}

		pkt.DecRef()
	}
	return nil
}
