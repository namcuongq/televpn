package network

import (
	"televpn/core"

	"github.com/fasthttp/websocket"
)

func Tun2SocketWithEn(src core.CommTCPConn, dest *websocket.Conn, key []byte) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, err := src.Read(buf)
		if err != nil {
			break
		}
		payload := buf[0:nr]

		payloadEn, err := AESEncrypt(key, payload)
		if err != nil {
			continue
		}

		err = dest.WriteMessage(websocket.BinaryMessage, payloadEn)
		if err != nil {
			break
		}
	}
}

func Socket2TunWithEn(src *websocket.Conn, dest core.CommTCPConn, key []byte) {
	for {
		_, messageEn, err := src.ReadMessage()
		if err != nil {
			break
		}

		message, err := AESDecrypt(key, messageEn)
		if err != nil {
			continue
		}

		_, err = dest.Write(message)
		if err != nil {
			break
		}
	}
}

func Tun2Socket(src core.CommTCPConn, dest *websocket.Conn) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		nr, err := src.Read(buf)
		if err != nil {
			break
		}
		payload := buf[0:nr]

		err = dest.WriteMessage(websocket.BinaryMessage, payload)
		if err != nil {
			break
		}
	}
}

func Socket2Tun(src *websocket.Conn, dest core.CommTCPConn) {
	for {
		_, message, err := src.ReadMessage()
		if err != nil {
			break
		}

		_, err = dest.Write(message)
		if err != nil {
			break
		}
	}
}
