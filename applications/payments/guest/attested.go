package payments

import (
	"encoding/binary"
	"fmt"
)

// AttestedKeyID returns platform.data.key_id of a VersionedAttestation from the guest's /v1/Attest, decoding the
// MessagePack subset dstack-compat/guest_attest.pack writes.
func AttestedKeyID(blob []byte) ([]byte, error) {
	v, n, e := unpack(blob, 0)
	if e != nil {
		return nil, e
	}
	if n != len(blob) {
		return nil, fmt.Errorf("trailing bytes after attestation")
	}
	a, _ := v.(map[string]any)
	p, _ := a["platform"].(map[string]any)
	d, _ := p["data"].(map[string]any)
	if a["version"] != 1 || p["kind"] != "apple-app-attest" {
		return nil, fmt.Errorf("not an apple-app-attest v1 attestation")
	}
	ints, _ := d["key_id"].([]any)
	if len(ints) != 32 {
		return nil, fmt.Errorf("attestation key_id must be 32 bytes")
	}
	kid := make([]byte, 32)
	for i, x := range ints {
		b, ok := x.(int)
		if !ok || b > 255 {
			return nil, fmt.Errorf("attestation key_id byte")
		}
		kid[i] = byte(b)
	}
	return kid, nil
}

func unpack(b []byte, i int) (any, int, error) {
	if i >= len(b) {
		return nil, 0, fmt.Errorf("truncated attestation")
	}
	t := b[i]
	need := func(n int) error {
		if i+n > len(b) {
			return fmt.Errorf("truncated attestation")
		}
		return nil
	}
	switch {
	case t < 0x80:
		return int(t), i + 1, nil
	case t == 0xcc:
		if e := need(2); e != nil {
			return nil, 0, e
		}
		return int(b[i+1]), i + 2, nil
	case t >= 0xa0 && t <= 0xbf, t == 0xd9, t == 0xda:
		n, s := int(t&31), i+1
		if t == 0xd9 {
			if e := need(2); e != nil {
				return nil, 0, e
			}
			n, s = int(b[i+1]), i+2
		} else if t == 0xda {
			if e := need(3); e != nil {
				return nil, 0, e
			}
			n, s = int(binary.BigEndian.Uint16(b[i+1:])), i+3
		}
		if s+n > len(b) {
			return nil, 0, fmt.Errorf("truncated attestation")
		}
		return string(b[s : s+n]), s + n, nil
	case t >= 0x80 && t <= 0x9f, t == 0xdc, t == 0xde:
		isMap, n, p := t < 0x90 || t == 0xde, int(t&15), i+1
		if t >= 0xdc {
			if e := need(3); e != nil {
				return nil, 0, e
			}
			n, p = int(binary.BigEndian.Uint16(b[i+1:])), i+3
		}
		items := make([]any, 0, n)
		count := n
		if isMap {
			count = 2 * n
		}
		for k := 0; k < count; k++ {
			x, q, e := unpack(b, p)
			if e != nil {
				return nil, 0, e
			}
			items, p = append(items, x), q
		}
		if !isMap {
			return items, p, nil
		}
		m := map[string]any{}
		for k := 0; k < count; k += 2 {
			key, ok := items[k].(string)
			if !ok {
				return nil, 0, fmt.Errorf("attestation map key")
			}
			if _, dup := m[key]; dup {
				return nil, 0, fmt.Errorf("duplicate attestation map key")
			}
			m[key] = items[k+1]
		}
		return m, p, nil
	}
	return nil, 0, fmt.Errorf("unsupported MessagePack type 0x%02x", t)
}
