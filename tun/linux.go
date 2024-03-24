//go:build linux

package tun

import "golang.zx2c4.com/wireguard/tun"

func createTun(tunDevice string, mtu int, tunAddr, tunMask, tunGW string, tunDNSs []string) (*DevReadWriteCloser, error) {
	tunDev, err := tun.CreateTUN(tunDevice, mtu)
	if err != nil {
		return nil, err
	}

	return &DevReadWriteCloser{
		tunDev.(*tun.NativeTun),
		nil,
		nil,
	}, nil
}
