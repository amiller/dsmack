package payments

import (
	"fmt"
	"math/big"
	"strings"
)

const GuestEscrow = "0xca184cFC10F55b67F8aFB42029D768eC6E6F36ad"
const GuestClaimType = "Claim(address operator,bytes32 termsHash,uint256 cumulativeOwed)"

// GuestClaim uses GuestEscrow's buyer-salted domain. The key is the same
// ephemeral key bound into this run's node attestation.
type GuestClaim struct {
	Escrow         string `json:"escrow"`
	Key            string `json:"key"`
	Buyer          string `json:"buyer"`
	TermsHash      string `json:"terms_hash"`
	Operator       string `json:"operator"`
	CumulativeOwed string `json:"cumulative_owed"`
	Signature      string `json:"signature"`
}

func GuestClaimDigest(buyer, operator, termsHash, cumulativeOwed string) ([]byte, error) {
	b, err := raw(buyer, 20)
	if err != nil {
		return nil, err
	}
	o, err := raw(operator, 20)
	if err != nil {
		return nil, err
	}
	t, err := raw(termsHash, 32)
	if err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(cumulativeOwed, 10)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 || n.String() != cumulativeOwed {
		return nil, fmt.Errorf("claim amount")
	}
	a, _ := raw(GuestEscrow, 20)
	domain := hash(join(hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")), hash([]byte("LayoverGuestEscrow")), hash([]byte("1")), uintWord(84532), padded(a), padded(b)))
	body := hash(join(hash([]byte(GuestClaimType)), padded(o), t, word(cumulativeOwed)))
	return hash(join([]byte{0x19, 0x01}, domain, body)), nil
}

// GuestKeyReport is the exact abi.encode(key,operator) consumed by
// registerGuestKey, separate from the challenge-bound peer admission proof.
func (m *Meter) GuestKeyReport() []byte {
	k, _ := raw(m.ReceiptSigner, 20)
	o, _ := raw(m.Operator, 20)
	return join(padded(k), padded(o))
}

func (m *Meter) SignGuestClaim(buyer, termsHash, cumulativeOwed string) (GuestClaim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := GuestClaimDigest(buyer, m.Operator, termsHash, cumulativeOwed)
	if err != nil {
		return GuestClaim{}, err
	}
	key := strings.ToLower(buyer) + ":" + strings.ToLower(termsHash)
	if m.claimTotals == nil {
		m.claimTotals = map[string]*big.Int{}
	}
	owed, _ := new(big.Int).SetString(cumulativeOwed, 10)
	if prev := m.claimTotals[key]; prev != nil && owed.Cmp(prev) < 0 {
		return GuestClaim{}, fmt.Errorf("claim amount regressed")
	}
	m.claimTotals[key] = owed
	return GuestClaim{GuestEscrow, m.ReceiptSigner, buyer, termsHash, m.Operator, cumulativeOwed, sign(m.key, d)}, nil
}
