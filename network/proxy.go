package network

import (
	"io"
	"net"
	"time"
)

func ReadFull(r net.Conn, buf []byte, timeout time.Duration) error {
	r.SetReadDeadline(time.Now().Add(timeout))
	for i := 0; i < len(buf); {
		if n, err := r.Read(buf[i:]); err != nil {
			return err
		} else {
			i += n
		}
	}
	r.SetReadDeadline(time.Time{})
	return nil
}

func ReadN(r io.Reader, buf []byte, l int) error {
	for i := 0; i < l; {
		if n, err := r.Read(buf[i:]); err != nil {
			return err
		} else {
			i += n
		}
	}
	return nil
}

func SendEn(dst io.Writer, src io.Reader, key []byte) {
	size := 31 * 1024
	buf := make([]byte, size)
	header := make([]byte, 2)

	l := 0
	for {
		nr, er := src.Read(buf)
		if er != nil {
			break
		}
		if nr > 0 {
			m, er := AESEncrypt(key, buf[0:nr])
			if er != nil {
				break
			}

			l = len(m)
			header[0], header[1] = byte(l>>8), byte(l&255)

			_, er = dst.Write(header)
			if er != nil {
				break
			}

			_, er = dst.Write(m)
			if er != nil {
				break
			}
		}
	}

}

func ReadDe(dst io.Writer, src io.Reader, key []byte) {
	size := 32 * 1024
	buf := make([]byte, size)
	for {
		err := ReadN(src, buf, 2)
		if err != nil {
			break
		}
		nr := int(buf[0])<<8 + int(buf[1])

		if nr > 0 {
			er := ReadN(src, buf, nr)
			if er != nil {
				break
			}

			l := buf[0:nr]
			m, er := AESDecrypt(key, l)
			if er != nil {
				break
			}

			_, er = dst.Write(m)
			if er != nil {
				break
			}
		}
	}

}
