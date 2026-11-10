// check-manifest MANIFEST: decode a packed compute-node compose manifest's PAYMENTS_CONFIG with the guest's own decoder
// (payments.ParseConfig, the one paid.go calls at boot). Exits non-zero with the decoder's error.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	payments "dsmack-payments"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	check(err)
	var manifest struct {
		Compose string `json:"docker_compose_file"`
	}
	check(json.Unmarshal(raw, &manifest))
	var compose struct {
		Services map[string]struct {
			Environment map[string]string `json:"environment"`
		} `json:"services"`
	}
	check(json.Unmarshal([]byte(manifest.Compose), &compose))
	env, ok := compose.Services["node"].Environment["PAYMENTS_CONFIG"]
	if !ok {
		check(fmt.Errorf("no PAYMENTS_CONFIG in services.node.environment"))
	}
	cfg, err := payments.ParseConfig(env)
	check(err)
	fmt.Printf("PAYMENTS_CONFIG decodes: node %s\n", cfg.Node)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "PAYMENTS_CONFIG:", err)
		os.Exit(1)
	}
}
