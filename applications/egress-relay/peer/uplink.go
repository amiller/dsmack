package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// profile accepts a single wg-quick uplink. Hooks and unknown options fail closed.
// Its IPC representation and keys stay in memory and must never be logged.
func profile(raw string) (addresses, dns []netip.Addr, mtu int, ipc string, err error) {
	mtu = 1280
	section := ""
	peers := 0
	var privateKey, publicKey string
	seen := map[string]bool{}
	fail := func() ([]netip.Addr, []netip.Addr, int, string, error) {
		return nil, nil, 0, "", fmt.Errorf("invalid or unsupported WireGuard profile")
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			section = line
			if line == "[Peer]" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		field := section + k
		if !ok || seen[field] {
			return fail()
		}
		seen[field] = true
		switch field {
		case "[Interface]PrivateKey", "[Peer]PublicKey", "[Peer]PresharedKey":
			key, e := base64.StdEncoding.DecodeString(v)
			if e != nil || len(key) != 32 {
				return fail()
			}
			name := map[string]string{"PrivateKey": "private_key", "PublicKey": "public_key", "PresharedKey": "preshared_key"}[k]
			setting := name + "=" + hex.EncodeToString(key) + "\n"
			switch k {
			case "PrivateKey":
				privateKey = setting
			case "PublicKey":
				publicKey = setting
			default:
				ipc += setting
			}
			clear(key)
		case "[Interface]Address":
			for _, a := range strings.Split(v, ",") {
				p, e := netip.ParsePrefix(strings.TrimSpace(a))
				if e != nil {
					return fail()
				}
				addresses = append(addresses, p.Addr())
			}
		case "[Interface]DNS":
			for _, a := range strings.Split(v, ",") {
				p, e := netip.ParseAddr(strings.TrimSpace(a))
				if e != nil {
					return fail()
				}
				dns = append(dns, p)
			}
		case "[Interface]MTU":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1280 || n > 9000 {
				return fail()
			}
			mtu = n
		case "[Peer]Endpoint":
			// An IP endpoint avoids resolving the VPN endpoint outside its uplink.
			if _, e := netip.ParseAddrPort(v); e != nil {
				return fail()
			}
			ipc += "endpoint=" + v + "\n"
		case "[Peer]AllowedIPs":
			ipc += "replace_allowed_ips=true\n"
			for _, a := range strings.Split(v, ",") {
				p, e := netip.ParsePrefix(strings.TrimSpace(a))
				if e != nil {
					return fail()
				}
				ipc += "allowed_ip=" + p.String() + "\n"
			}
		case "[Peer]PersistentKeepalive":
			n, e := strconv.ParseUint(v, 10, 16)
			if e != nil {
				return fail()
			}
			ipc += "persistent_keepalive_interval=" + strconv.FormatUint(n, 10) + "\n"
		default:
			return fail()
		}
	}
	if scanner.Err() != nil || peers != 1 || len(addresses) == 0 || len(dns) == 0 {
		return fail()
	}
	for _, f := range []string{"[Interface]PrivateKey", "[Peer]PublicKey", "[Peer]Endpoint", "[Peer]AllowedIPs"} {
		if !seen[f] {
			return fail()
		}
	}
	ipc = privateKey + "replace_peers=true\n" + publicKey + ipc
	return
}

func uplink(raw []byte) (*netstack.Net, func(), error) {
	addresses, dns, mtu, ipc, err := profile(string(raw))
	clear(raw)
	if err != nil {
		return nil, nil, err
	}
	tun, stack, err := netstack.CreateNetTUN(addresses, dns, mtu)
	if err != nil {
		return nil, nil, err
	}
	// WireGuard IPC errors may include key material: never expose their text.
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if dev.IpcSet(ipc) != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("WireGuard configuration failed")
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("WireGuard startup failed")
	}
	return stack, dev.Close, nil
}
