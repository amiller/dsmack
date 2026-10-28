package main

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
)

func testProfile() string {
	key := base64.StdEncoding.EncodeToString([]byte("synthetic-test-key-not-a-secret!"))
	return "# Proton-style single uplink\n[Interface]\nPrivateKey = " + key + `
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ` + key + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
`
}

func TestProtonProfileKeepsTunnelDNSAndRoutes(t *testing.T) {
	addresses, dns, mtu, ipc, err := profile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("10.2.0.2") {
		t.Fatal("profile did not preserve the client tunnel address")
	}
	if len(dns) != 1 || dns[0] != netip.MustParseAddr("10.2.0.1") {
		t.Fatal("profile did not preserve tunnel DNS")
	}
	if mtu < 1280 {
		t.Fatal("MTU cannot carry IPv6")
	}
	for _, setting := range []string{"allowed_ip=0.0.0.0/0\n", "allowed_ip=::/0\n", "endpoint=192.0.2.1:51820\n", "persistent_keepalive_interval=25\n"} {
		if !strings.Contains(ipc, setting) {
			t.Fatal("profile lost an uplink route or endpoint setting")
		}
	}
}

// UAPI selects a peer at public_key; settings written earlier target no peer.
func TestProfileSelectsPeerBeforeItsSettings(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("synthetic-test-key-not-a-secret!"))
	raw := `[Interface]
Address = 10.2.0.2/32
DNS = 10.2.0.1
PrivateKey = ` + key + `
[Peer]
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
PublicKey = ` + key + "\n"
	_, _, _, ipc, err := profile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ipc, "private_key=") {
		t.Fatal("UAPI device private key must precede peer configuration")
	}
	publicKey := strings.Index(ipc, "\npublic_key=")
	for _, setting := range []string{"\nendpoint=", "\nreplace_allowed_ips=", "\nallowed_ip="} {
		position := strings.Index(ipc, setting)
		if publicKey < 0 || position < 0 || position < publicKey {
			t.Fatal("UAPI peer settings must follow the peer public key")
		}
	}
}

// A wg-quick hook must not become a process launch, and errors must not disclose keys.
func TestProfileRejectsHooksAndMalformedKeysWithoutDisclosure(t *testing.T) {
	key := "synthetic-malformed-private-key"
	validKey := base64.StdEncoding.EncodeToString([]byte("synthetic-test-key-not-a-secret!"))
	for name, raw := range map[string]string{
		"hook":        strings.Replace(testProfile(), "[Peer]", "PostUp = echo hook\n[Peer]", 1),
		"private key": strings.Replace(testProfile(), "PrivateKey = "+base64.StdEncoding.EncodeToString([]byte("synthetic-test-key-not-a-secret!")), "PrivateKey = "+key, 1),
		"public key":  strings.Replace(testProfile(), "PublicKey = "+base64.StdEncoding.EncodeToString([]byte("synthetic-test-key-not-a-secret!")), "PublicKey = "+key, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, ipc, err := profile(raw)
			if err == nil {
				t.Fatal("unsafe profile accepted")
			}
			if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), validKey) || ipc != "" {
				t.Fatal("rejected profile disclosed key material")
			}
		})
	}
}
