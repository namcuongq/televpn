package vpn

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"televpn/core"
	"televpn/log"
	"televpn/network"
	"time"

	"github.com/fasthttp/websocket"
)

type slashFix struct {
	mux http.Handler
}

const (
	ERROR_AUTHENFAIL = "Authentication failed"
)

func (h *slashFix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	h.mux.ServeHTTP(w, r)
}

func StartServer(config Config) error {
	var vpn = &TeleVpnServer{}
	vpn.config = config
	vpn.setupAuthen()

	return vpn.startHTTP()
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
	var upgrader = websocket.Upgrader{}
	httpMux := http.NewServeMux()

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

	if t.config.SSL {
		httpMux.HandleFunc(DEFAULT_PATH_VPN, func(w http.ResponseWriter, r *http.Request) {
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

	httpMux.HandleFunc(DEFAULT_PATH, func(w http.ResponseWriter, r *http.Request) {
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

	if t.config.SSL {
		log.Info("Listen:", t.config.Server, "- SSL")
		return http.ListenAndServeTLS(t.config.Server, t.config.SSLCrt, t.config.SSLKey, &slashFix{httpMux})
	}

	log.Info("Listen:", t.config.Server, "- No SSL")
	return http.ListenAndServe(t.config.Server, &slashFix{httpMux})
}
