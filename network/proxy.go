package network

import (
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
