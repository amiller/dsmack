package main

import "crypto/ecdh"

func public(k *ecdh.PrivateKey) []byte { return k.PublicKey().Bytes()[1:] }
