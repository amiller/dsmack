// Start the measured hostname gateway before the guest's loopback-only peer.
package main

import (
	"bufio"
	"dsmack-peer/p2p"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: browser-guest <tunnel hostname> <relay PeerId> <seconds>")
	}
	logs, err := os.Create("/workspace/artifacts/gateway-log")
	if err != nil {
		log.Fatal(err)
	}
	defer logs.Close()
	gateway := exec.Command("/usr/local/bin/egress-policy", "-policy", "/policy.json", "-http", "127.0.0.1:8080", "-dns", "127.0.0.1:5353", "-answer-ip", "127.0.0.1", "-websocket-host", os.Args[1])
	gateway.Stdout = logs
	stderr, err := gateway.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err = gateway.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { gateway.Process.Signal(os.Interrupt); gateway.Wait() }()
	scan := bufio.NewScanner(stderr)
	if !scan.Scan() || scan.Text() != "egress gateway ready" {
		log.Fatal("gateway startup failed")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			log.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The peer has only a loopback WebSocket transport; the gateway owns upstream TLS.
	os.Setenv("DSMACK_LOCAL_WS", "1")
	os.Args = []string{os.Args[0], "serve", fmt.Sprintf("/ip4/127.0.0.1/tcp/8080/ws/p2p/%s", os.Args[2]), os.Args[3]}
	p2p.Main()
}
