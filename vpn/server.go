package vpn

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"televpn/core"
	"televpn/log"
	"televpn/network"
	"time"
	_ "time/tzdata"

	"github.com/fasthttp/websocket"
)

type slashFix struct {
	mux http.Handler
}

const (
	ERROR_AUTHENFAIL = "Authentication failed"
	TIME_FORMAT      = "15:04"
)

func (h *slashFix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	h.mux.ServeHTTP(w, r)
}

func StartServer(config Config) error {
	var vpn = &TeleVpnServer{}
	vpn.config = config

	vpn.setupCopyFunc()
	err := vpn.setupCrontab()
	if err != nil {
		return err
	}

	vpn.setupAuthen()
	return vpn.startHTTP()
}

func (t *TeleVpnServer) setupCopyFunc() {
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
				log.Debug("auto off http server")
				t.Tun2Socket = func(ct core.CommTCPConn, c *websocket.Conn, b []byte) {
					c.Close()
				}
				t.Socket2Tun = func(c *websocket.Conn, ct core.CommTCPConn, b []byte) {
					c.Close()
				}

				time.Sleep(sleepStart)
				log.Debug("auto on http server")
				t.setupCopyFunc()

				sleepStop = 24 * time.Hour
			}
		}()
	}

	return
}

func (t *TeleVpnServer) setupAuthen() {
	t.Users = make(map[string]User, 0)
	t.Clients = Client{data: make(map[string]*websocket.Conn, 0)}
	for _, u := range t.config.Users {
		t.Users[u.Username] = u
		t.Clients.AddNill(u.Ipaddress)
	}
}

func (t *TeleVpnServer) parseKeyUserAddr(authenHeader, token string) ([]byte, string, string, error) {
	if len(authenHeader) < 1 || len(token) < 1 {
		return nil, "", "", nil
	}

	userByte, err := base64.URLEncoding.DecodeString(authenHeader)
	if err != nil {
		return nil, "", "", err
	}

	tokenByte, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, "", "", err
	}
	user := string(userByte)
	u, found := t.Users[user]
	if !found {
		return nil, "", "", nil
	}

	key := makeKey(u)
	out, err := network.AESDecrypt(key, tokenByte)
	if err != nil {
		return nil, "", "", err
	}
	dataKeyAddr := string(out)
	i := strings.Index(dataKeyAddr, ":")
	if i < 1 {
		return nil, "", "", nil
	}

	sessionKey := dataKeyAddr[:i]
	addr := dataKeyAddr[i+1:]

	return []byte(sessionKey), user, addr, nil
}

func (t *TeleVpnServer) startHTTP() error {
	t.setupHTTPHandle()
	return t.runHTTP()
}

func (t *TeleVpnServer) runHTTP() error {
	t.httpServer = &http.Server{Addr: t.config.Server, Handler: &slashFix{t.httpMux}, ErrorLog: httpLogger()}
	if t.config.SSL {
		log.Info("Listen:", t.config.Server, "- SSL")
		return t.httpServer.ListenAndServeTLS(t.config.SSLCrt, t.config.SSLKey)
	}

	log.Info("Listen:", t.config.Server, "- No SSL")
	return t.httpServer.ListenAndServe()
}

func (t *TeleVpnServer) stopHTTP() error {
	return t.httpServer.Close()
}

func (t *TeleVpnServer) setupHTTPHandle() {
	var upgrader = websocket.Upgrader{}
	t.httpMux = http.NewServeMux()

	if t.config.SSL {
		t.httpMux.HandleFunc(DEFAULT_PATH_VPN, func(w http.ResponseWriter, r *http.Request) {
			userEn := r.Header.Get("Etag")
			authenData := r.Header.Get("X-Id")
			key, user, addr, err := t.parseKeyUserAddr(userEn, authenData)
			if err != nil || len(addr) < 1 || key == nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(ERROR_AUTHENFAIL))
				log.Debug(r.RemoteAddr, ERROR_AUTHENFAIL, err)
				return
			}

			currentConn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer currentConn.Close()
			u := t.Users[user]

			targetConn, found := t.Clients.Get(u.Ipaddress)
			if !found {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(ERROR_AUTHENFAIL))
				log.Debug(r.RemoteAddr, ERROR_AUTHENFAIL, err)
				return
			}

			if targetConn != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("You have logged in at another location"))
				return
			}
			defer func() {
				t.Clients.AddNill(u.Ipaddress)
			}()
			t.Clients.Set(u.Ipaddress, currentConn)

			for {
				err = currentConn.SetReadDeadline(time.Now().Add(time.Duration(t.config.MTU+5) * time.Second))
				if err != nil {
					break
				}

				_, message, err := currentConn.ReadMessage()
				if err != nil {
					break
				}

				if string(message) == "ping" {
					continue
				}

				header := network.ParseHeaderPacket(message)
				dstConn, found := t.Clients.Get(header.IPDst.String())
				if !found || dstConn == nil {
					continue
				}

				err = dstConn.WriteMessage(websocket.BinaryMessage, message)
				if err != nil {
					continue
				}
			}

		})

	}

	t.httpMux.HandleFunc(DEFAULT_PATH, func(w http.ResponseWriter, r *http.Request) {
		userEn := r.Header.Get("Etag")
		authenData := r.Header.Get("X-Id")
		key, _, addr, err := t.parseKeyUserAddr(userEn, authenData)
		if err != nil || len(addr) < 1 || key == nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(ERROR_AUTHENFAIL))
			log.Debug(r.RemoteAddr, ERROR_AUTHENFAIL, err)
			return
		}

		currentConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer currentConn.Close()

		remoteConn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer remoteConn.Close()

		go t.Tun2Socket(remoteConn, currentConn, key)
		t.Socket2Tun(currentConn, remoteConn, key)
	})
}
