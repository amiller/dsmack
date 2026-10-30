package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// The plaintext hop is confined to this measured guest. The gateway originates
// TLS with the broker's original hostname through the host CONNECT proxy.
type brokerGatewayTransport struct {
	hostname string
	http     *http.Transport
}

func (t *brokerGatewayTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Hostname() != t.hostname || (request.URL.Port() != "" && request.URL.Port() != "443") ||
		(request.Host != "" && request.Host != request.URL.Host) || request.URL.User != nil {
		return nil, fmt.Errorf("broker gateway authority")
	}
	local := request.Clone(request.Context())
	local.URL.Scheme = "http"
	local.URL.Host = t.hostname
	local.Host = t.hostname
	return t.http.RoundTrip(local)
}

func gatewayBrokerClient(broker *url.URL, gateway string) (*http.Client, error) {
	u, err := url.Parse(gateway)
	if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() ||
		u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		broker.Scheme != "https" || broker.Hostname() == "" || broker.User != nil || broker.Port() != "" && broker.Port() != "443" {
		return nil, fmt.Errorf("broker gateway requires HTTPS authority and explicit loopback HTTP endpoint")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(broker.Hostname(), "80") {
			return nil, fmt.Errorf("broker gateway destination")
		}
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, u.Host)
	}}
	return &http.Client{Timeout: 30 * time.Second, Transport: &brokerGatewayTransport{broker.Hostname(), transport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

type gatewayChild struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

type nodeGateways struct {
	children []*gatewayChild
	failed   chan error
	log      *os.File
	dir      string
}

func (g *nodeGateways) close() {
	for _, c := range g.children {
		select {
		case <-c.done:
		default:
			if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil && err != os.ErrProcessDone {
				log.Printf("stop %s gateway: %v", c.name, err)
			}
		}
	}
	for _, c := range g.children {
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
			log.Printf("kill unresponsive %s gateway", c.name)
			c.cmd.Process.Kill()
			<-c.done
		}
	}
	if g.log != nil {
		g.log.Close()
	}
	if g.dir != "" {
		os.RemoveAll(g.dir)
	}
}

func (g *nodeGateways) start(name, listen string, policy map[string]any, hostname string) error {
	file := filepath.Join(g.dir, name+".json")
	if err := os.WriteFile(file, canon(policy), 0600); err != nil {
		return err
	}
	args := []string{"-policy", file, "-http", listen, "-dns", "", "-upstream-proxy", os.Getenv("HTTPS_PROXY")}
	if hostname != "" {
		args = append(args, "-websocket-host", hostname)
	}
	cmd := exec.Command("/usr/local/bin/dsmack-egress", args...)
	cmd.Stdout = g.log
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	child := &gatewayChild{name: name, cmd: cmd, done: make(chan struct{})}
	g.children = append(g.children, child)
	go func() {
		child.err = cmd.Wait()
		close(child.done)
		g.failed <- fmt.Errorf("%s gateway exited: %v", name, child.err)
	}()
	ready := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(stderr)
		line, err := reader.ReadString('\n')
		if err != nil || line != "egress gateway ready\n" {
			ready <- fmt.Errorf("%s gateway startup: %s (%v)", name, strings.TrimSpace(line), err)
			return
		}
		ready <- nil
		io.Copy(os.Stderr, reader)
	}()
	select {
	case err = <-ready:
		if err != nil {
			return err
		}
	case <-child.done:
		return fmt.Errorf("%s gateway startup exit: %v", name, child.err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%s gateway startup timeout", name)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-child.done:
			return fmt.Errorf("%s gateway exited: %v", name, child.err)
		default:
		}
		conn, err := net.DialTimeout("tcp", listen, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("%s gateway listener timeout", name)
}

func brokerGatewayPolicy(broker, index *url.URL) map[string]any {
	base := strings.TrimRight(broker.Path, "/")
	paths := []string{index.Path, base + "/nodes", base + "/payments/challenge", base + "/payments/receipts", base + "/agent/receipt"}
	return map[string]any{"rules": []any{map[string]any{
		"name": broker.Hostname(), "port": 443, "methods": []string{"GET", "POST"}, "paths": paths,
		"max_request_bytes": 256 << 10, "max_response_bytes": 256 << 10,
		"upload_bytes": 8 << 20, "download_bytes": 8 << 20, "requests": 512, "requests_per_minute": 120,
	}}}
}

func websocketGatewayPolicy() map[string]any {
	return map[string]any{"rules": []any{map[string]any{
		"name": "*.trycloudflare.com", "port": 443, "methods": []string{"GET"}, "paths": []string{"/"},
		"websocket_seconds": 960, "max_request_bytes": 1 << 20, "max_response_bytes": 4 << 20,
		"upload_bytes": 32 << 20, "download_bytes": 32 << 20, "requests": 8, "requests_per_minute": 8,
	}}}
}

var quickTunnelHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$`)

type tunnelHint struct {
	URL       string `json:"url"`
	RelayPeer string `json:"relayPeer"`
	ExpiresAt int64  `json:"expiresAt"`
}

func selectTunnel(raw []byte, expected peer.ID, now int64) (string, error) {
	var hints []tunnelHint
	if len(raw) > 16384 {
		return "", fmt.Errorf("tunnel index byte bound")
	}
	if err := json.Unmarshal(raw, &hints); err != nil || len(hints) > 32 {
		return "", fmt.Errorf("tunnel index array")
	}
	var best *tunnelHint
	for i := range hints {
		hint := &hints[i]
		if hint.RelayPeer == expected.String() && hint.ExpiresAt > now && (best == nil || hint.ExpiresAt > best.ExpiresAt) {
			best = hint
		}
	}
	if best == nil {
		return "", fmt.Errorf("no live tunnel for measured relay PeerId")
	}
	u, err := url.Parse(best.URL)
	if err != nil || u.Scheme != "wss" || u.User != nil || u.Port() != "" || u.Path != "/" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !quickTunnelHost.MatchString(u.Host) {
		return "", fmt.Errorf("tunnel requires a one-label trycloudflare WSS URL")
	}
	return u.Hostname(), nil
}

func startNodeGateways(relay, brokerURL, indexURL string) (_ *nodeGateways, publicRelay string, err error) {
	if os.Getenv("BROKER_GATEWAY") != "http://127.0.0.1:18080" || os.Getenv("HTTPS_PROXY") != "http://192.168.127.254:18484" {
		return nil, "", fmt.Errorf("Mac gateway endpoints differ from measured configuration")
	}
	info, err := peer.AddrInfoFromString(relay)
	if err != nil || len(info.Addrs) != 1 || info.Addrs[0].String() != "/ip4/127.0.0.1/tcp/18082/ws" {
		return nil, "", fmt.Errorf("Mac relay requires the loopback WebSocket endpoint")
	}
	broker, err := url.Parse(brokerURL)
	if err != nil {
		return nil, "", err
	}
	index, err := url.Parse(indexURL)
	if err != nil || broker.Scheme != "https" || index.Scheme != "https" || index.Host != broker.Host || index.User != nil ||
		index.Path == "" || index.RawQuery != "" || index.ForceQuery || index.Fragment != "" {
		return nil, "", fmt.Errorf("tunnel index must use the measured HTTPS broker authority")
	}
	connection, directErr := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second)
	if directErr == nil {
		connection.Close()
		return nil, "", fmt.Errorf("direct Internet egress unexpectedly allowed")
	}
	if err = os.WriteFile("/workspace/artifacts/egress-checks", []byte("direct 1.1.1.1:443 blocked\n"), 0644); err != nil {
		return nil, "", err
	}
	g := &nodeGateways{failed: make(chan error, 2)}
	g.log, err = os.Create("/workspace/artifacts/gateway-log")
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil {
			fmt.Fprintf(g.log, "%s\n", canon(map[string]string{"event": "gateway_startup_error", "error": err.Error()}))
			g.close()
		}
	}()
	g.dir, err = os.MkdirTemp("/run/dsmack", "node-gateways-")
	if err != nil {
		return nil, "", err
	}
	if err = g.start("broker", "127.0.0.1:18080", brokerGatewayPolicy(broker, index), ""); err != nil {
		return nil, "", err
	}
	client, err := brokerClient(brokerURL)
	if err != nil {
		return nil, "", err
	}
	response, err := client.Get(indexURL)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel index: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("tunnel index HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil {
		return nil, "", err
	}
	hostname, err := selectTunnel(raw, info.ID, time.Now().Unix())
	if err != nil {
		return nil, "", err
	}
	if err = g.start("websocket", "127.0.0.1:18082", websocketGatewayPolicy(), hostname); err != nil {
		return nil, "", err
	}
	if err = os.Setenv("DSMACK_LOCAL_WS", "1"); err != nil {
		return nil, "", err
	}
	if err = os.Setenv("AGENT_NETWORK_ALLOWLIST", string(canon([]string{broker.Hostname(), hostname}))); err != nil {
		return nil, "", err
	}
	return g, "/dns4/" + hostname + "/tcp/443/wss/p2p/" + info.ID.String(), nil
}
