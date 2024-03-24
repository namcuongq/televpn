//go:build windows
// +build windows

package tun

import (
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	_ "golang.zx2c4.com/wireguard/windows/tunnel"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

//go:embed wintun/x86/wintun.dll
var wintunX86DLL []byte

//go:embed wintun/amd64/wintun.dll
var wintunAmd64DLL []byte

//go:embed wintun/arm/wintun.dll
var wintunArmDLL []byte

//go:embed wintun/arm64/wintun.dll
var wintunArm64DLL []byte

func createTun(tunDevice string, mtu int, tunAddr, tunMask, tunGW string, tunDNSs []string) (*DevReadWriteCloser, error) {
	err := checkWintunDLL()
	if err != nil {
		return nil, fmt.Errorf("error check wintun.dll %v", err)
	}

	tunDev, err := tun.CreateTUN(tunDevice, mtu)
	if err != nil {
		return nil, err
	}

	err = windowsSetIPAddress4(tunDev.(*tun.NativeTun), tunAddr, tunMask, tunGW, tunDNSs)
	if err != nil {
		return nil, err
	}

	return &DevReadWriteCloser{
		tunDev.(*tun.NativeTun),
		getDefaultGatewayWindows,
		windowsRouteTraffic,
	}, nil
}

func checkWintunDLL() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}

	wintunPath := path.Join(dir, "wintun.dll")
	if _, err := os.Stat(wintunPath); err == nil {
		return nil
	} else {
		if !os.IsNotExist(err) {
			return err
		}
	}

	var dllByte []byte
	switch runtime.GOARCH {
	case "amd64":
		dllByte = wintunAmd64DLL
	case "x86":
		dllByte = wintunX86DLL
	case "arm":
		dllByte = wintunArmDLL
	case "arm64":
		dllByte = wintunArm64DLL
	}

	return os.WriteFile(wintunPath, dllByte, os.ModePerm)
}

func windowsRouteTraffic(tunDevice, src, dst string) error {
	// execCommand(`netsh interface ipv4 add route 0.0.0.0/0 "tun0" 172.16.0.2 metric=1`)
	routeCmd := exec.Command("netsh", "interface", "ipv4", "add", "route", src, tunDevice, dst, "metric=1")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route traffic to tun err: %v %s", err, string(output))
	}

	return nil
}

func windowsSetIPAddress4(tunDev *tun.NativeTun, addr, mask, gateway string, tunDNSs []string) error {
	luid := winipcfg.LUID(tunDev.LUID())
	ipnet := net.IPNet{
		IP:   net.ParseIP(addr).To4(),
		Mask: net.IPMask(net.ParseIP(mask).To4()),
	}
	addresses := append([]netip.Prefix{}, netip.MustParsePrefix(ipnet.String()))
	err := luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	if err != nil {
		return err
	}

	dnss := []netip.Addr{}
	for _, d := range tunDNSs {
		dnss = append(dnss, netip.MustParseAddr(d))
	}

	if len(dnss) > 0 {
		err = luid.SetDNS(windows.AF_INET, dnss, []string{})
	}
	return err
}

func windowsSetIpAddress6(tunDev *tun.NativeTun, addr, mask, gateway, tunDNS string) error {
	luid := winipcfg.LUID(tunDev.LUID())

	ipnet := net.IPNet{
		IP:   net.ParseIP(addr).To16(),
		Mask: net.IPMask(net.ParseIP(mask).To16()),
	}
	addresses := append([]netip.Prefix{}, netip.MustParsePrefix(ipnet.String()))

	err := luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	if err != nil {
		return err
	}

	err = luid.SetDNS(windows.AF_INET6, []netip.Addr{netip.MustParseAddr(tunDNS)}, []string{})
	return err
}

func getDefaultGatewayWindows() (WindowsRouter, error) {
	var route = WindowsRouter{}
	routeCmd := exec.Command("route", "print", "0.0.0.0")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return route, fmt.Errorf("get default gateway err: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	sep := 0
	for idx, line := range lines {
		if sep == 3 {
			if len(lines) <= idx+2 {
				return route, fmt.Errorf("get default gateway err: no gateway")
			}

			fields := strings.Fields(lines[idx+2])
			if len(fields) < 5 {
				return route, fmt.Errorf("get default gateway err: can't parse")
			}

			route = WindowsRouter{
				Destination: fields[0],
				Netmask:     fields[1],
				Gateway:     fields[2],
				Interface:   fields[3],
				Metric:      fields[4],
			}
			break
		}
		if strings.HasPrefix(line, "=======") {
			sep++
			continue
		}
	}

	return route, err
}
