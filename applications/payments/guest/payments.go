// Package payments implements the Base Sepolia paid grant and cumulative receipt wire format.
package payments

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"
)

func hash(b []byte) []byte  { h := sha3.NewLegacyKeccak256(); h.Write(b); return h.Sum(nil) }
func hexed(b []byte) string { return "0x" + hex.EncodeToString(b) }
func raw(s string, n int) ([]byte, error) {
	b, e := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if e != nil || len(b) != n {
		return nil, fmt.Errorf("hex length %d", n)
	}
	return b, nil
}
func word(s string) []byte {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		panic("integer word")
	}
	return n.FillBytes(make([]byte, 32))
}
func uintWord(n int64) []byte { return word(strconv.FormatInt(n, 10)) }
func padded(b []byte) []byte  { v := make([]byte, 32); copy(v[32-len(b):], b); return v }
func join(parts ...[]byte) []byte {
	var out []byte
	for _, b := range parts {
		out = append(out, b...)
	}
	return out
}

const ReceiptType = "Receipt(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)"
const GrantType = "Grant(uint256 purchaseId,bytes32 node,bytes32 runId,bytes32 buyerKey,uint8 unit,uint128 amount,uint64 issuedAt,uint64 serviceUntil,bytes32 destinationPolicyHash)"

func Domain(escrow string) ([]byte, error) {
	a, e := raw(escrow, 20)
	if e != nil {
		return nil, e
	}
	return hash(join(hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")), hash([]byte("DsmackUsageEscrow")), hash([]byte("2")), uintWord(84532), padded(a))), nil
}
func typed(escrow string, body []byte) ([]byte, error) {
	d, e := Domain(escrow)
	if e != nil {
		return nil, e
	}
	return hash(join([]byte{0x19, 0x01}, d, hash(body))), nil
}
func address(pub *secp.PublicKey) string { return hexed(hash(pub.SerializeUncompressed()[1:])[12:]) }
func sign(key *secp.PrivateKey, digest []byte) string {
	s := ecdsa.SignCompact(key, digest, false)
	return hexed(append(s[1:], s[0]))
}
func recover(digest []byte, s string) (string, error) {
	v, e := raw(s, 65)
	if e != nil {
		return "", e
	}
	if v[64] != 27 && v[64] != 28 {
		return "", fmt.Errorf("recovery ID")
	}
	var scalar secp.ModNScalar
	if scalar.SetByteSlice(v[32:64]) || scalar.IsZero() || scalar.IsOverHalfOrder() {
		return "", fmt.Errorf("noncanonical signature")
	}
	pub, _, e := ecdsa.RecoverCompact(append([]byte{v[64]}, v[:64]...), digest)
	if e != nil {
		return "", e
	}
	return address(pub), nil
}

type Config struct {
	Node                  string `json:"node"`
	Escrow                string `json:"escrow"`
	Operator              string `json:"operator"`
	GrantSigner           string `json:"grantSigner"`
	EnrollmentKeyID       string `json:"enrollmentKeyId"`
	BuildID               string `json:"buildId"`
	DestinationPolicyHash string `json:"destinationPolicyHash"`
	RunExpires            int64  `json:"runExpires"`
}
type Registration struct {
	Config
	RunID         string `json:"runId"`
	RunNonce      string `json:"runNonce"`
	ReceiptSigner string `json:"receiptSigner"`
	Challenge     string `json:"challenge"`
}
type Meter struct {
	Registration
	key       *secp.PrivateKey
	mu        sync.Mutex
	sequences map[string]int64
	closed    map[string]bool
}

func New(cfg Config) (*Meter, error) {
	for _, v := range []string{cfg.Escrow, cfg.Operator, cfg.GrantSigner} {
		if _, e := raw(v, 20); e != nil {
			return nil, e
		}
	}
	for _, v := range []string{cfg.Node, cfg.EnrollmentKeyID, cfg.BuildID, cfg.DestinationPolicyHash} {
		if _, e := raw(v, 32); e != nil {
			return nil, e
		}
	}
	if cfg.RunExpires <= time.Now().Unix() {
		return nil, fmt.Errorf("paid run expired")
	}
	key, e := secp.GeneratePrivateKey()
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	kid, _ := raw(cfg.EnrollmentKeyID, 32)
	return &Meter{Registration: Registration{Config: cfg, RunID: hexed(hash(join(kid, nonce))), RunNonce: hexed(nonce), ReceiptSigner: address(key.PubKey())}, key: key, sequences: map[string]int64{}, closed: map[string]bool{}}, nil
}
func (m *Meter) Binding(peer, compose, image string) ([]byte, error) {
	escrow, _ := raw(m.Escrow, 20)
	node, _ := raw(m.Node, 32)
	run, _ := raw(m.RunID, 32)
	operator, _ := raw(m.Operator, 20)
	signer, _ := raw(m.ReceiptSigner, 20)
	build, _ := raw(m.BuildID, 32)
	c, e := raw(compose, 32)
	if e != nil {
		return nil, e
	}
	i, e := raw(image, 32)
	if e != nil {
		return nil, e
	}
	p := sha256.Sum256([]byte(peer))
	return hash(join(hash([]byte("DsmackPaymentsNodeV2")), uintWord(84532), padded(escrow), node, run, padded(operator), padded(signer), p[:], c, i, build, uintWord(m.RunExpires))), nil
}
func (m *Meter) Report(peer, compose, image string, legacy []byte, challenge string) ([]byte, error) {
	b, e := m.Binding(peer, compose, image)
	if e != nil {
		return nil, e
	}
	c, e := raw(challenge, 32)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(join(legacy, c))
	return join(b, h[:]), nil
}

type Grant struct {
	PurchaseID            string `json:"purchaseId"`
	Node                  string `json:"node"`
	RunID                 string `json:"runId"`
	BuyerKey              string `json:"buyerKey"`
	Unit                  uint8  `json:"unit"`
	Amount                string `json:"amount"`
	IssuedAt              int64  `json:"issuedAt"`
	ServiceUntil          int64  `json:"serviceUntil"`
	DestinationPolicyHash string `json:"destinationPolicyHash"`
}
type Envelope struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}

func decimal(s string, bits int) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() > 0 && n.BitLen() <= bits && n.String() == s
}
func (g Grant) Digest(escrow string) ([]byte, error) {
	if !decimal(g.PurchaseID, 256) || !decimal(g.Amount, 128) {
		return nil, fmt.Errorf("grant integers")
	}
	n, e := raw(g.Node, 32)
	if e != nil {
		return nil, e
	}
	run, e := raw(g.RunID, 32)
	if e != nil {
		return nil, e
	}
	b, e := raw(g.BuyerKey, 32)
	if e != nil {
		return nil, e
	}
	p, e := raw(g.DestinationPolicyHash, 32)
	if e != nil {
		return nil, e
	}
	return typed(escrow, join(hash([]byte(GrantType)), word(g.PurchaseID), n, run, b, uintWord(int64(g.Unit)), word(g.Amount), uintWord(g.IssuedAt), uintWord(g.ServiceUntil), p))
}
func (m *Meter) Verify(rawGrant []byte, client string, unit uint8, now int64) (Grant, error) {
	var e Envelope
	if err := json.Unmarshal(rawGrant, &e); err != nil {
		return e.Grant, err
	}
	g := e.Grant
	if g.Node != m.Node || g.RunID != m.RunID || g.Unit != unit || g.IssuedAt > now || g.IssuedAt < 0 || g.ServiceUntil <= now || g.ServiceUntil > g.IssuedAt+600 || g.ServiceUntil > m.RunExpires || g.DestinationPolicyHash != m.DestinationPolicyHash {
		return g, fmt.Errorf("paid grant terms")
	}
	digest, err := g.Digest(m.Escrow)
	if err != nil {
		return g, err
	}
	signer, err := recover(digest, e.Signature)
	if err != nil || !strings.EqualFold(signer, m.GrantSigner) {
		return g, fmt.Errorf("paid grant signer")
	}
	id, err := peer.Decode(client)
	if err != nil {
		return g, err
	}
	pub, err := id.ExtractPublicKey()
	if err != nil {
		return g, err
	}
	buyer, err := pub.Raw()
	if err != nil || hexed(buyer) != g.BuyerKey {
		return g, fmt.Errorf("paid grant buyer PeerId")
	}
	amount, _ := strconv.ParseInt(g.Amount, 10, 64)
	maximum := int64(64 << 20)
	if unit == 1 {
		maximum = 600
	}
	if amount < 1 || amount > maximum {
		return g, fmt.Errorf("paid grant budget")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed[g.PurchaseID] {
		return g, fmt.Errorf("purchase already closed")
	}
	return g, nil
}

type Receipt struct {
	PurchaseID   string `json:"purchaseId"`
	Sequence     int64  `json:"sequence"`
	Used         string `json:"used"`
	EndedAt      int64  `json:"endedAt"`
	FinalReceipt bool   `json:"finalReceipt"`
}
type SignedReceipt struct {
	Receipt   Receipt `json:"receipt"`
	Signature string  `json:"signature"`
}

func (r Receipt) Digest(escrow string) ([]byte, error) {
	f := int64(0)
	if r.FinalReceipt {
		f = 1
	}
	return typed(escrow, join(hash([]byte(ReceiptType)), word(r.PurchaseID), uintWord(r.Sequence), word(r.Used), uintWord(r.EndedAt), uintWord(f)))
}
func (m *Meter) Receipt(g Grant, used int64, final bool) (SignedReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	amount, _ := strconv.ParseInt(g.Amount, 10, 64)
	if m.closed[g.PurchaseID] || used < 0 || used > amount {
		return SignedReceipt{}, fmt.Errorf("receipt closed or over budget")
	}
	m.sequences[g.PurchaseID]++
	r := Receipt{g.PurchaseID, m.sequences[g.PurchaseID], strconv.FormatInt(used, 10), min(time.Now().Unix(), g.ServiceUntil), final}
	d, e := r.Digest(m.Escrow)
	if e != nil {
		return SignedReceipt{}, e
	}
	if final {
		m.closed[g.PurchaseID] = true
	}
	return SignedReceipt{r, sign(m.key, d)}, nil
}

// VerifyStop authorizes orderly shutdown by the attested operator, so the VM
// can flush its result evidence after all jobs and receipts have completed.
func (m *Meter) VerifyStop(signature string, expires int64) error {
	now := time.Now().Unix()
	if expires < now || expires > now+300 {
		return fmt.Errorf("operator stop expired")
	}
	node, _ := raw(m.RunID, 32)
	d, e := typed(m.Escrow, join(hash([]byte("Stop(bytes32 node,uint64 expires)")), node, uintWord(expires)))
	if e != nil {
		return e
	}
	signer, e := recover(d, signature)
	if e != nil || !strings.EqualFold(signer, m.Operator) {
		return fmt.Errorf("operator stop signature")
	}
	return nil
}
