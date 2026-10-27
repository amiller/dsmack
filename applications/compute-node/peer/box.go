package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type box struct {
	CT  string `json:"ct"`
	EPK string `json:"epk"`
	IV  string `json:"iv"`
}

func public(k *ecdh.PrivateKey) []byte { return k.PublicKey().Bytes()[1:] }
func boxKey(k *ecdh.PrivateKey, remote []byte, epk, recipient []byte, task string) (cipher.AEAD, error) {
	p, e := ecdh.P256().NewPublicKey(append([]byte{4}, remote...))
	if e != nil {
		return nil, e
	}
	z, e := k.ECDH(p)
	if e != nil {
		return nil, e
	}
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(z)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("dsmack.secret-release/1"))
	expand.Write(epk)
	expand.Write(recipient)
	expand.Write([]byte(task))
	expand.Write([]byte{1})
	block, e := aes.NewCipher(expand.Sum(nil))
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func seal(recipient []byte, task string, raw []byte) (box, error) {
	k, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return box{}, e
	}
	a, e := boxKey(k, recipient, public(k), recipient, task)
	if e != nil {
		return box{}, e
	}
	iv := make([]byte, 12)
	if _, e = rand.Read(iv); e != nil {
		return box{}, e
	}
	return box{EPK: hex.EncodeToString(public(k)), IV: hex.EncodeToString(iv), CT: hex.EncodeToString(a.Seal(nil, iv, raw, nil))}, nil
}
func openBox(k *ecdh.PrivateKey, task string, b box) ([]byte, error) {
	epk, e := hex.DecodeString(b.EPK)
	if e != nil {
		return nil, e
	}
	iv, e := hex.DecodeString(b.IV)
	if e != nil || len(iv) != 12 {
		return nil, fmt.Errorf("iv")
	}
	ct, e := hex.DecodeString(b.CT)
	if e != nil {
		return nil, e
	}
	a, e := boxKey(k, epk, epk, public(k), task)
	if e != nil {
		return nil, e
	}
	return a.Open(nil, iv, ct, nil)
}
