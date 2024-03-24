package network

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"televpn/log"

	"github.com/fasthttp/websocket"
)

type PacketHeader struct {
	IPSrc    net.IP
	IPDst    net.IP
	IsIPv6   bool
	Protocol string
}

func ParseHeaderPacket(buf []byte) PacketHeader {
	var ipHeader PacketHeader
	switch buf[0] & 0xF0 {
	case 0x40:
		ipHeader.IPSrc = net.IP(buf[12:16])
		ipHeader.IPDst = net.IP(buf[16:20])
		ipHeader.Protocol = fmt.Sprintf("%d", buf[9])
	case 0x60:
		ipHeader.IsIPv6 = true
		ipHeader.IPSrc = net.IP(buf[8:24])
		ipHeader.IPDst = net.IP(buf[24:40])
		ipHeader.Protocol = fmt.Sprintf("%d", buf[7])
	}

	return ipHeader
}

func UUID() (uuid string) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Error("error uuid:", err)
		return
	}

	uuid = fmt.Sprintf("%X%X%X%X%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	return
}

func CIDRToMask(ip string) string {
	_, ipv4Net, _ := net.ParseCIDR(ip)
	return ipv4MaskString(ipv4Net.Mask)
}

func GetIp(str string) string {
	if strings.Contains(str, ":") {
		return str[:strings.Index(str, ":")]
	}
	return str[:strings.Index(str, "/")]
}

func ipv4MaskString(m []byte) string {
	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ConnectWebSocket(d *websocket.Dialer, u, host, user string, token []byte) (*websocket.Conn, error) {
	src, resp, err := d.Dial(
		u,
		http.Header{
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"},
			"X-Id":       []string{base64.URLEncoding.EncodeToString(token)}, // tmpkey + ip:port
			"Host":       []string{host},
			"ETag":       []string{base64.URLEncoding.EncodeToString([]byte(user))},
		})
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("error connect server %v", string(b))
		}
		return nil, err
	}
	return src, nil
}
