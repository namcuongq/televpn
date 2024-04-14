package vpn

import (
	"fmt"
	"strings"
	"televpn/log"
	"televpn/proxy"
	"time"
	_ "time/tzdata"
)

const (
	TIME_FORMAT = "15:04"
)

func StartServer(config proxy.Config) error {
	var vpn = &TeleVpnServer{}
	vpn.config = config

	// vpn.setupAuthen()
	var err error

	log.Info("Server mode:", config.Mode)
	switch config.Mode {
	case "ws":
		vpn.s, err = proxy.NewWSServer(config)
		if err != nil {
			return err
		}
	case "tcp":
		vpn.s, err = proxy.NewTCPServer(config)
		if err != nil {
			return err
		}
	}
	defer vpn.s.Stop()
	log.Info("Server run on:", config.Server)

	err = vpn.setupCrontab()
	if err != nil {
		return err
	}

	return vpn.s.Handle()
}

func (t *TeleVpnServer) setupCrontab() (err error) {
	if len(t.config.Auto) > 0 {
		autoArr := strings.Split(t.config.Auto, "-")
		if len(autoArr) < 2 {
			err = fmt.Errorf("Wrong DateTime Format")
			return
		}

		var start, end time.Time
		start, err = time.Parse(TIME_FORMAT, autoArr[0])
		if err != nil {
			return
		}

		end, err = time.Parse(TIME_FORMAT, autoArr[1])
		if err != nil {
			return
		}

		loc, _ := time.LoadLocation("Asia/Bangkok")
		now := time.Now().In(loc)
		nowTime, _ := time.Parse(TIME_FORMAT, fmt.Sprintf("%d:%d", now.Hour(), now.Minute()))
		if end.Before(nowTime) {
			end = end.Add(24 * time.Hour)
		}

		if start.Before(end) {
			start = start.Add(24 * time.Hour)
		}

		sleepStop := end.Sub(nowTime)
		sleepStart := start.Sub(end)

		go func() {
			for {
				time.Sleep(sleepStop)
				log.Debug("VPN server is paused!")
				t.s.Pause()
				time.Sleep(sleepStart)
				log.Debug("VPN server is resumed!")
				t.s.Resume()
				sleepStop = 24 * time.Hour
			}
		}()
	}

	return
}
