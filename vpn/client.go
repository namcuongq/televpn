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
	"televpn/proxy"
	"televpn/tun"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func StartClient(c proxy.Config) error {
	var vpn TeleVpnClient
	vpn.config = c
	var tunConfig = tun.Config{
		Name: "tun0",
		MTU:  c.MTU,
		Addr: c.Address,
		GW:   c.DefaultGateway,
		DNS:  c.DNSServer,
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
	t.key = makeKey(proxy.User{Username: t.config.User, Password: t.config.Pass, Ipaddress: t.config.Address})
}

func (t *TeleVpnClient) setupDialer(ip string) error {
	var tlsConfig *tls.Config
	caCert, err := ioutil.ReadFile(t.config.SSLCrt)
	if err != nil {
		return fmt.Errorf("Error opening cert file "+t.config.SSLCrt+", error:", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig = &tls.Config{
		ServerName: t.config.HostHeader,
		RootCAs:    caCertPool,
		// InsecureSkipVerify: true,
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

	switch t.config.Mode {
	case "ws":
		t.proxyClient, err = proxy.NewWSClient(t.config.Address,
			t.config.HostHeader, t.config.Server,
			tlsConfig, &t.defaultDialerTCP)
		if err != nil {
			return fmt.Errorf("setup proxy client err: %v", err)
		}
	case "tcp":
		t.proxyClient, err = proxy.NewTCPClient(t.config.Address,
			t.config.HostHeader, t.config.Server,
			tlsConfig, &t.defaultDialerTCP)
		if err != nil {
			return fmt.Errorf("setup proxy client err: %v", err)
		}
	}

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

	textKey := []byte(network.UUID())
	authenData, err := network.AESEncrypt([]byte(t.key), textKey)
	if err != nil {
		return err
	}

	t.proxyClient.Forward(conn, authenData)
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
			// t.publicWS.Send(buf[:recvLen])
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
