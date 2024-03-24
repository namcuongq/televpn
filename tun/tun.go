package tun

import (
	"televpn/network"
)

type WindowsRouter struct {
	Destination string
	Netmask     string
	Gateway     string
	Interface   string
	Metric      string
}

type Config struct {
	Name string
	MTU  int
	Addr string
	GW   string
	DNS  []string
}

func NewTun(c Config) (*DevReadWriteCloser, error) {
	return createTun(c.Name, c.MTU, c.Addr, network.CIDRToMask(c.Addr+"/32"), c.GW, c.DNS)
}
