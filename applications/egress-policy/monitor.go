package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

//go:embed monitor/registry.json
var monitorRegistry []byte

type classifier interface{ check(string) (string, error) }
type promptGuard struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func registeredMonitor(hash, description string) (string, error) {
	var registry map[string]map[string]any
	if err := json.Unmarshal(monitorRegistry, &registry); err != nil {
		return "", err
	}
	for name, entry := range registry {
		text, err := json.Marshal(entry)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(text)
		if hash == hex.EncodeToString(digest[:]) && description == string(text) {
			return name, nil
		}
	}
	return "", fmt.Errorf("unregistered monitor policy")
}

func startPromptGuard() (*promptGuard, error) {
	cmd := exec.Command("/opt/monitor/venv/bin/python", "/opt/monitor/promptguard.py", "/opt/monitor/weights")
	// Never copy classifier diagnostics or input to the host's captured stderr.
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	p := &promptGuard{cmd: cmd, input: input, output: bufio.NewReader(output)}
	line, err := p.line(120 * time.Second)
	if err != nil || line != "ready\n" {
		p.close()
		return nil, fmt.Errorf("monitor startup failed")
	}
	return p, nil
}

func (p *promptGuard) close() { p.input.Close(); p.cmd.Process.Kill(); p.cmd.Wait() }
func (p *promptGuard) line(timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() { line, err := p.output.ReadString('\n'); done <- result{line, err} }()
	select {
	case value := <-done:
		return value.line, value.err
	case <-time.After(timeout):
		p.cmd.Process.Kill()
		return "", fmt.Errorf("monitor timed out")
	}
}
func (p *promptGuard) check(text string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	request, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return "", err
	}
	if _, err = p.input.Write(append(request, '\n')); err != nil {
		return "", err
	}
	line, err := p.line(120 * time.Second)
	if err != nil {
		return "", err
	}
	var response struct {
		Code string `json:"code"`
	}
	if err = json.Unmarshal([]byte(line), &response); err != nil {
		return "", err
	}
	if response.Code != "" && response.Code != "PG2_PROMPT_ATTACK" {
		return "", fmt.Errorf("monitor code outside enum")
	}
	return response.Code, nil
}

// Only the encrypted MCP session receives these results. No audit event is emitted.
func monitorHandler(model classifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var request struct {
			Text string `json:"text"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "monitor input", 400)
			return
		}
		code := ""
		if model != nil {
			var err error
			code, err = model.check(request.Text)
			if err != nil {
				http.Error(w, "MONITOR_UNAVAILABLE", 503)
				return
			}
		}
		body, _ := json.Marshal(map[string]string{"code": code})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(append(body, bytes.Repeat([]byte(" "), 128-len(body))...))
	}
}
