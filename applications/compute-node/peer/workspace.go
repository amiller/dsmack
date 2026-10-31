package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const workspaceTool = "dsmack_workspace"
const workspaceChunk = 512 << 10

var workspaceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type workspaceBox struct {
	EPK string `json:"epk"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

// This is the existing browser P-256/HKDF/AES-GCM envelope. Only the per-workspace
// key crosses it; the user's data key never enters the guest.
func openWorkspaceBox(secret *ecdh.PrivateKey, label string, box workspaceBox) ([]byte, error) {
	if secret == nil || len(box.EPK) != 128 || len(box.IV) != 24 || len(box.CT) > 32768 {
		return nil, fmt.Errorf("workspace envelope")
	}
	epk, err := hex.DecodeString(box.EPK)
	if err != nil {
		return nil, fmt.Errorf("workspace envelope")
	}
	remote, err := ecdh.P256().NewPublicKey(append([]byte{4}, epk...))
	if err != nil {
		return nil, fmt.Errorf("workspace envelope")
	}
	shared, err := secret.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("workspace envelope")
	}
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(shared)
	clear(shared)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("dsmack.secret-release/1"))
	expand.Write(epk)
	expand.Write(public(secret))
	expand.Write([]byte(label))
	expand.Write([]byte{1})
	block, err := aes.NewCipher(expand.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("workspace envelope")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv, err := hex.DecodeString(box.IV)
	if err != nil || len(iv) != aead.NonceSize() {
		return nil, fmt.Errorf("workspace envelope")
	}
	ct, err := hex.DecodeString(box.CT)
	if err != nil {
		return nil, fmt.Errorf("workspace envelope")
	}
	raw, err := aead.Open(nil, iv, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("workspace envelope authentication")
	}
	return raw, nil
}

type workspaceSession struct {
	mu      sync.Mutex
	id      string
	pending map[string]string
}

func rpcID(raw json.RawMessage) string {
	var id any
	if json.Unmarshal(raw, &id) != nil {
		return ""
	}
	return string(canon(id))
}

// Bind is decrypted only on the authenticated guest side. Never retain its key
// in session metadata, errors, receipts or logs.
func (w *workspaceSession) request(n *engine, grantID string, line []byte) ([]byte, error) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string                     `json:"name"`
			Arguments map[string]json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("agent MCP invalid JSON")
	}
	if m.Method != "tools/call" || m.Params.Name != workspaceTool {
		return line, nil
	}
	var op string
	json.Unmarshal(m.Params.Arguments["operation"], &op)
	if op != "bind" {
		return line, nil
	}
	var sealed workspaceBox
	if len(m.Params.Arguments["key"]) != 0 || json.Unmarshal(m.Params.Arguments["sealed"], &sealed) != nil {
		return nil, fmt.Errorf("sealed workspace binding required")
	}
	raw, err := openWorkspaceBox(n.secret, grantID+"/workspace", sealed)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var binding struct {
		WorkspaceID string          `json:"workspaceId"`
		Key         string          `json:"key"`
		Head        json.RawMessage `json:"head"`
	}
	if json.Unmarshal(raw, &binding) != nil || !workspaceID.MatchString(binding.WorkspaceID) || len(binding.Key) != 64 {
		return nil, fmt.Errorf("workspace binding fields")
	}
	key, err := hex.DecodeString(binding.Key)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("workspace binding key")
	}
	clear(key)
	if len(binding.Head) == 0 {
		binding.Head = json.RawMessage("null")
	}
	var message map[string]json.RawMessage
	json.Unmarshal(line, &message)
	// Preserve the SDK's MCP2026 metadata envelope and any progress token.
	// Only replace sealed arguments with the private Unix binding.
	var params map[string]json.RawMessage
	json.Unmarshal(message["params"], &params)
	params["arguments"] = canon(map[string]any{"operation": "bind", "workspaceId": binding.WorkspaceID, "key": binding.Key, "head": binding.Head})
	message["params"] = canon(params)
	w.mu.Lock()
	if w.pending == nil {
		w.pending = map[string]string{}
	}
	w.pending[rpcID(m.ID)] = binding.WorkspaceID
	w.mu.Unlock()
	return canon(message), nil
}
func (w *workspaceSession) observe(line []byte) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError    bool `json:"isError"`
			Structured struct {
				WorkspaceID string `json:"workspaceId"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(line, &m) != nil {
		return
	}
	id := rpcID(m.ID)
	w.mu.Lock()
	defer w.mu.Unlock()
	expected, ok := w.pending[id]
	if !ok {
		return
	}
	delete(w.pending, id)
	if len(m.Error) == 0 && !m.Result.IsError && m.Result.Structured.WorkspaceID == expected {
		w.id = expected
	}
}

type workspaceMCP struct {
	conn   net.Conn
	reader *bufio.Reader
	next   int
}

func openWorkspaceMCP(socket string, deadline time.Time) (*workspaceMCP, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	c := &workspaceMCP{conn: conn, reader: bufio.NewReader(conn)}
	// MCP2026 has per-request envelopes and server/discover; initialize and
	// notifications/initialized belong to the earlier protocol handshake.
	if err = c.rpc("server/discover", map[string]any{}, nil); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}
func workspaceMCPMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "dsmack-workspace-seal", "version": "1"},
	}
}
func (c *workspaceMCP) rpc(method string, params any, out any) error {
	// MCP2026 is self-describing on every request, including discovery.
	fields, ok := params.(map[string]any)
	if !ok {
		return fmt.Errorf("workspace MCP request parameters")
	}
	fields["_meta"] = workspaceMCPMeta()
	c.next++
	id := c.next
	if _, err := c.conn.Write(append(canon(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}), '\n')); err != nil {
		return err
	}
	for {
		line, err := readWorkspaceLine(c.reader)
		if err != nil {
			return err
		}
		var message struct {
			ID     int             `json:"id"`
			Error  json.RawMessage `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(line, &message) != nil {
			return fmt.Errorf("workspace MCP response")
		}
		if message.ID != id {
			continue
		}
		if len(message.Error) != 0 {
			return fmt.Errorf("workspace MCP request refused")
		}
		if out != nil {
			return json.Unmarshal(message.Result, out)
		}
		return nil
	}
}
func readWorkspaceLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, prefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(line)+len(part) > 1<<20 {
			return nil, fmt.Errorf("workspace MCP response limit")
		}
		line = append(line, part...)
		if !prefix {
			return line, nil
		}
	}
}
func (c *workspaceMCP) control(args map[string]any, out any) error {
	var result struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := c.rpc("tools/call", map[string]any{"name": workspaceTool, "arguments": args}, &result); err != nil {
		return err
	}
	if result.IsError {
		return fmt.Errorf("workspace operation refused")
	}
	raw := result.Structured
	if len(raw) == 0 && len(result.Content) > 0 && result.Content[0].Type == "text" {
		raw = []byte(result.Content[0].Text)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
func (n *engine) workspacePost(ctx context.Context, client *http.Client, broker, session, op, id string, fields map[string]any, out any) error {
	body := map[string]any{"action": "workspace-" + op, "sessionId": session, "node_peer": n.node, "workspaceId": id, "issuedAt": time.Now().Unix()}
	for k, v := range fields {
		body[k] = v
	}
	body["sig"] = hex.EncodeToString(ed25519.Sign(n.signer, canon(body)))
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(broker, "/")+"/workspaces/"+op, bytes.NewReader(canon(body)))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("workspace %s transport: %w", op, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("workspace %s HTTP %d", op, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
}
func (w *workspaceSession) save(n *engine, socket, broker, session string, client *http.Client) error {
	w.mu.Lock()
	id := w.id
	w.mu.Unlock()
	if id == "" {
		return nil
	}
	deadline := n.until.Add(-time.Second)
	if !deadline.After(time.Now()) {
		return fmt.Errorf("workspace seal has no remaining guest time")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	c, err := openWorkspaceMCP(socket, deadline)
	if err != nil {
		return err
	}
	defer c.conn.Close()
	var head struct {
		WorkspaceID  string `json:"workspaceId"`
		Version      int64  `json:"version"`
		PreviousHash string `json:"previousHash"`
		Hash         string `json:"hash"`
		Size         int64  `json:"size"`
	}
	if err = c.control(map[string]any{"operation": "seal"}, &head); err != nil {
		return err
	}
	if head.WorkspaceID != id || head.Size < 16 || head.Size > 224<<20 {
		return fmt.Errorf("workspace seal metadata")
	}
	// Retain only encrypted bytes before depending on the network. The compose
	// exports these files into the original result disk if upload cannot finish.
	directory := filepath.Dir(n.resultPath)
	if n.resultPath == "" {
		directory = "/workspace/artifacts"
	}
	file, err := os.CreateTemp(directory, "workspace-seal-*.part")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	digest := sha256.New()
	for offset := int64(0); offset < head.Size; {
		var part struct {
			Offset int64  `json:"offset"`
			Data   string `json:"data"`
		}
		if err = c.control(map[string]any{"operation": "read", "offset": offset, "length": min(int64(workspaceChunk), head.Size-offset)}, &part); err != nil {
			file.Close()
			return err
		}
		bytes, decodeErr := base64.StdEncoding.DecodeString(part.Data)
		if decodeErr != nil || part.Offset != offset || len(bytes) == 0 || len(bytes) > workspaceChunk || int64(len(bytes)) > head.Size-offset {
			file.Close()
			return fmt.Errorf("workspace retained chunk")
		}
		if _, err = file.Write(bytes); err != nil {
			file.Close()
			return err
		}
		digest.Write(bytes)
		offset += int64(len(bytes))
	}
	if hex.EncodeToString(digest.Sum(nil)) != head.Hash {
		file.Close()
		return fmt.Errorf("workspace retained hash")
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(directory, "workspace-seal.bin")); err != nil {
		return err
	}
	retained := map[string]any{"action": "workspace-retained", "sessionId": session, "node_peer": n.node, "workspaceId": id, "issuedAt": time.Now().Unix(), "head": map[string]any{"workspaceId": head.WorkspaceID, "version": head.Version, "previousHash": head.PreviousHash, "hash": head.Hash, "size": head.Size}}
	retained["sig"] = hex.EncodeToString(ed25519.Sign(n.signer, canon(retained)))
	metadata, err := os.OpenFile(filepath.Join(directory, "workspace-seal.json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = metadata.Write(canon(retained)); err == nil {
		err = metadata.Sync()
	}
	closeErr := metadata.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	var begin struct {
		UploadID  string          `json:"uploadId"`
		Offset    int64           `json:"offset"`
		Committed bool            `json:"committed"`
		Head      json.RawMessage `json:"head"`
	}
	if err = n.workspacePost(ctx, client, broker, session, "begin", id, map[string]any{"version": head.Version, "previousHash": head.PreviousHash, "hash": head.Hash, "size": head.Size}, &begin); err != nil {
		return err
	}
	if !begin.Committed {
		if begin.UploadID == "" || begin.Offset < 0 || begin.Offset > head.Size {
			return fmt.Errorf("workspace upload offset")
		}
		for offset := begin.Offset; offset < head.Size; {
			var chunk struct {
				Offset int64  `json:"offset"`
				Data   string `json:"data"`
			}
			if err = c.control(map[string]any{"operation": "read", "offset": offset, "length": min(int64(workspaceChunk), head.Size-offset)}, &chunk); err != nil {
				return err
			}
			data, err := base64.StdEncoding.DecodeString(chunk.Data)
			if err != nil || chunk.Offset != offset || len(data) == 0 || len(data) > workspaceChunk || int64(len(data)) > head.Size-offset {
				return fmt.Errorf("workspace cipher chunk")
			}
			var ack struct {
				Offset int64 `json:"offset"`
			}
			if err = n.workspacePost(ctx, client, broker, session, "chunk", id, map[string]any{"uploadId": begin.UploadID, "offset": offset, "data": chunk.Data}, &ack); err != nil {
				return err
			}
			if ack.Offset != offset+int64(len(data)) {
				return fmt.Errorf("workspace upload acknowledgement")
			}
			offset = ack.Offset
		}
		var committed struct {
			Head json.RawMessage `json:"head"`
		}
		if err = n.workspacePost(ctx, client, broker, session, "commit", id, map[string]any{"uploadId": begin.UploadID}, &committed); err != nil {
			return err
		}
		begin.Head = committed.Head
	}
	if err = c.control(map[string]any{"operation": "commit", "head": begin.Head}, nil); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "workspace-seal.bin"), nil, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "workspace-seal.json"), []byte("null"), 0600)
}
