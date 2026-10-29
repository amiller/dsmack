// Build together with compute-node/peer/box.go in a temporary directory.
package main

import (
    "crypto/ecdh"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "os"
)

func main() {
    var request struct { Mode, Key, Task, Plain string; Box box }
    if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil { panic(err) }
    key, err := hex.DecodeString(request.Key); if err != nil { panic(err) }
    if request.Mode == "open" {
        private, err := ecdh.P256().NewPrivateKey(key); if err != nil { panic(err) }
        raw, err := openBox(private, request.Task, request.Box); if err != nil { panic(err) }
        if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"plain":base64.StdEncoding.EncodeToString(raw)}); err != nil { panic(err) }
    } else {
        plain, err := base64.StdEncoding.DecodeString(request.Plain); if err != nil { panic(err) }
        result, err := seal(key, request.Task, plain); if err != nil { panic(err) }
        if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
    }
}
