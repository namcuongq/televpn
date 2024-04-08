package network

import (
	"televpn/core"

	"github.com/fasthttp/websocket"
)

func Tun2SocketWithEn(src core.CommTCPConn, dest *websocket.Conn, key []byte) {
	defer func() {
		src.Close()
		dest.Close()
	}()
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
			break
		}

		err = dest.WriteMessage(websocket.BinaryMessage, payloadEn)
		if err != nil {
			break
		}
	}
}

func Socket2TunWithEn(src *websocket.Conn, dest core.CommTCPConn, key []byte) {
	defer func() {
		src.Close()
		dest.Close()
	}()
	for {
		_, messageEn, err := src.ReadMessage()
		if err != nil {
			break
		}

		message, err := AESDecrypt(key, messageEn)
		if err != nil {
			break
		}

		_, err = dest.Write(message)
		if err != nil {
			break
		}
	}
}

func Tun2Socket(src core.CommTCPConn, dest *websocket.Conn) {
	defer func() {
		src.Close()
		dest.Close()
	}()
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
	defer func() {
		src.Close()
		dest.Close()
	}()
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
