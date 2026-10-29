package p2p

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func backhaulLog(format string, args ...any) {
	fmt.Printf("%s broker backhaul %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
}

func backhaulFailure(stage string, err error) {
	cause := "io"
	var netError net.Error
	if errors.Is(err, context.Canceled) {
		cause = "cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netError) && netError.Timeout()) {
		cause = "timeout"
	} else if errors.Is(err, io.EOF) {
		cause = "eof"
	}
	backhaulLog("failed stage=%s cause=%s type=%T", stage, cause, err)
}

// backhaulListener supplies a loopback TCP stream to Go's existing Noise/yamux
// stack. Finite HTTP sends and long polls carry those bytes through the broker's
// shared HTTP worker, whose outer proxy does not support WebSocket upgrades.
func backhaulListener(raw string) (net.Listener, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.Path[len(u.Path)-1] == '/' {
		return nil, fmt.Errorf("broker HTTP backhaul origin")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return nil, fmt.Errorf("broker backhaul requires HTTPS")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go bridgeHTTP(conn, raw)
		}
	}()
	return listener, nil
}

func bridgeHTTP(conn net.Conn, raw string) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 25 * time.Second, MaxIdleConnsPerHost: 2}
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	request := func(method, path string, body []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, raw+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		return client.Do(req)
	}
	response, err := request("POST", "/open", nil)
	if err != nil {
		backhaulFailure("http_open", err)
		return
	}
	var opened struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&opened)
	response.Body.Close()
	id, hexErr := hex.DecodeString(opened.ID)
	if response.StatusCode != 200 || err != nil || hexErr != nil || len(id) != 32 {
		backhaulLog("HTTP open refused status=%d", response.StatusCode)
		return
	}
	path := "/" + opened.ID
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		req, _ := http.NewRequestWithContext(cleanupCtx, "DELETE", raw+path, nil)
		if response, err := client.Do(req); err == nil {
			response.Body.Close()
		}
	}()
	go func() {
		defer conn.Close()
		defer cancel()
		buffer := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				response, sendErr := request("POST", path+"/send", buffer[:n])
				if sendErr != nil {
					backhaulFailure("http_send", sendErr)
					return
				}
				response.Body.Close()
				if response.StatusCode != 204 {
					backhaulLog("HTTP send refused status=%d", response.StatusCode)
					return
				}
			}
			if err != nil {
				backhaulFailure("tcp_read", err)
				return
			}
		}
	}()
	for {
		response, err := request("GET", path+"/recv", nil)
		if err != nil {
			backhaulFailure("http_receive", err)
			return
		}
		if response.StatusCode == 204 {
			response.Body.Close()
			continue
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			backhaulLog("HTTP receive refused status=%d", response.StatusCode)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		if err != nil {
			backhaulFailure("http_receive_body", err)
			return
		}
		if len(raw) > 64<<10 {
			backhaulLog("HTTP receive body exceeded frame limit")
			return
		}
		if _, err := conn.Write(raw); err != nil {
			backhaulFailure("tcp_write", err)
			return
		}
	}
}

// maintainBackhaul authenticates the configured broker PeerId over the outbound
// connection. The broker can then open relay streams on that same connection;
// neither side needs an inbound route to the operator's LAN address.
func maintainBackhaul(ctx context.Context, h host.Host, raw, brokerID string) error {
	id, err := peer.Decode(brokerID)
	if err != nil {
		return err
	}
	listener, err := backhaulListener(raw)
	if err != nil {
		return err
	}
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	if err != nil {
		listener.Close()
		return err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		defer listener.Close()
		for {
			if ctx.Err() != nil {
				return
			}
			if h.Network().Connectedness(id) != network.Connected {
				h.Peerstore().ClearAddrs(id)
				dialCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				err := h.Connect(dialCtx, peer.AddrInfo{ID: id, Addrs: []ma.Multiaddr{addr}})
				cancel()
				if err != nil {
					backhaulFailure("noise_connect", err)
				} else {
					h.ConnManager().Protect(id, "broker-backhaul")
					backhaulLog("connected %s", id)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
	return nil
}
