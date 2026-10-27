package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

type stream interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetDeadline(time.Time) error
}
type dialFunc func(context.Context, string, string) (net.Conn, error)

// bridge preserves half closes so a client can send EOF and still receive a response.
func bridge(a stream, b stream) {
	done := make(chan struct{})
	go func() { io.Copy(a, b); a.CloseWrite(); close(done) }()
	io.Copy(b, a)
	b.CloseWrite()
	<-done
}

// socks handles RFC 1928 no-auth CONNECT; address resolution uses only dial.
func socks(s stream, dial dialFunc) error {
	defer s.Close()
	s.SetDeadline(time.Now().Add(30 * time.Second))
	var h [4]byte
	if _, err := io.ReadFull(s, h[:2]); err != nil {
		return err
	}
	if h[0] != 5 || h[1] == 0 {
		return fmt.Errorf("SOCKS greeting")
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(s, methods); err != nil {
		return err
	}
	auth := byte(255)
	for _, m := range methods {
		if m == 0 {
			auth = 0
		}
	}
	if _, err := s.Write([]byte{5, auth}); err != nil {
		return err
	}
	if auth != 0 {
		return fmt.Errorf("SOCKS authentication unsupported")
	}
	if _, err := io.ReadFull(s, h[:]); err != nil {
		return err
	}
	reply := func(code byte) error { _, e := s.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}); return e }
	if h[0] != 5 || h[2] != 0 {
		reply(1)
		return fmt.Errorf("SOCKS request")
	}
	if h[1] != 1 {
		reply(7)
		return fmt.Errorf("SOCKS supports CONNECT only")
	}
	var addr string
	switch h[3] {
	case 1, 4:
		n := 4
		if h[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(s, b); err != nil {
			return err
		}
		addr = net.IP(b).String()
	case 3:
		if _, err := io.ReadFull(s, h[:1]); err != nil {
			return err
		}
		if h[0] == 0 {
			reply(8)
			return fmt.Errorf("SOCKS empty hostname")
		}
		b := make([]byte, int(h[0]))
		if _, err := io.ReadFull(s, b); err != nil {
			return err
		}
		addr = string(b)
	default:
		reply(8)
		return fmt.Errorf("SOCKS address type")
	}
	if _, err := io.ReadFull(s, h[:2]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c, err := dial(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(int(binary.BigEndian.Uint16(h[:2])))))
	cancel()
	if err != nil {
		reply(5)
		return fmt.Errorf("uplink TCP dial failed")
	}
	defer c.Close()
	if err = reply(0); err != nil {
		return err
	}
	s.SetDeadline(time.Time{})
	bridge(s, c.(stream))
	return nil
}
