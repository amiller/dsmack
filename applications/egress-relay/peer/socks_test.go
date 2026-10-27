package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	return a, b
}

func readBytes(t *testing.T, r io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("SOCKS response %v, want %v", got, want)
	}
}

func completed(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS session did not finish")
		return nil
	}
}

// EOF must reach the destination without discarding the response it sends afterwards.
func TestConnectUsesUplinkDNSAndPreservesHalfClose(t *testing.T) {
	client, guest := tcpPair(t)
	uplink, destination := tcpPair(t)
	dialed := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- socks(guest, func(_ context.Context, network, address string) (net.Conn, error) {
			dialed <- network + " " + address
			return uplink, nil
		})
	}()
	response := make(chan error, 1)
	go func() {
		defer destination.Close()
		request, err := io.ReadAll(destination)
		if err == nil {
			_, err = destination.Write(append([]byte("reply:"), request...))
		}
		response <- err
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	readBytes(t, client, []byte{5, 0})
	host := "only-through-vpn.invalid"
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = append(request, 1, 187) // 443
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	readBytes(t, client, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if got := <-dialed; got != "tcp "+host+":443" {
		t.Fatalf("uplink destination %q", got)
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	back, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "reply:request" {
		t.Fatalf("response after request EOF: %q", back)
	}
	if err := completed(t, response); err != nil {
		t.Fatal(err)
	}
	if err := completed(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestBindAndUDPRejectedBeforeDial(t *testing.T) {
	for name, command := range map[string]byte{"BIND": 2, "UDP": 3} {
		t.Run(name, func(t *testing.T) {
			client, guest := tcpPair(t)
			dialed := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				done <- socks(guest, func(context.Context, string, string) (net.Conn, error) {
					dialed <- struct{}{}
					return nil, errors.New("unexpected dial")
				})
			}()
			client.Write([]byte{5, 1, 0})
			readBytes(t, client, []byte{5, 0})
			client.Write([]byte{5, command, 0, 1})
			readBytes(t, client, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			if completed(t, done) == nil {
				t.Fatal("unsupported SOCKS command accepted")
			}
			if len(dialed) != 0 {
				t.Fatal("unsupported command reached uplink dialer")
			}
		})
	}
}

func TestUnsupportedAuthenticationRejectedBeforeDial(t *testing.T) {
	client, guest := tcpPair(t)
	dialed := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- socks(guest, func(context.Context, string, string) (net.Conn, error) {
			dialed <- struct{}{}
			return nil, errors.New("unexpected dial")
		})
	}()
	client.Write([]byte{5, 1, 2})
	readBytes(t, client, []byte{5, 255})
	if completed(t, done) == nil {
		t.Fatal("unsupported authentication accepted")
	}
	if len(dialed) != 0 {
		t.Fatal("unsupported authentication reached uplink dialer")
	}
}
