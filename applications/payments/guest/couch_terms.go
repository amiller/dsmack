package payments

import (
 "encoding/json"
 "fmt"
 "math/big"
 "strings"
)

// CouchTerms binds execution to the exact canonical terms the buyer accepted.
// The signed broker grant carries the original JSON; its hash is the on-chain key.
type CouchTerms struct {
 Buyer string `json:"buyer"`
 TermsHash string `json:"termsHash"`
 Terms string `json:"terms"`
}
type couchPrice struct {
 Kind string `json:"kind"`
 ChainID int64 `json:"chain_id"`
 Escrow string `json:"escrow"`
 Token string `json:"token"`
 Mode string `json:"mode"`
 Operator string `json:"operator"`
 Minutes int64 `json:"minutes"`
 Rate int64 `json:"rate_layc_per_second"`
 Minimum int64 `json:"minimum_seconds"`
 Cap string `json:"cap"`
}

func (m *Meter) ValidateCouchTerms(t CouchTerms, seconds int64) error {
 if _,err:=raw(t.Buyer,20);err!=nil {return err}
 if strings.ToLower(hexed(hash([]byte(t.Terms))))!=strings.ToLower(t.TermsHash) {return fmt.Errorf("couch terms hash")}
 var p couchPrice
 if err:=json.Unmarshal([]byte(t.Terms),&p);err!=nil {return err}
 if p.Kind!="layover-terms/1" || p.ChainID!=84532 || !strings.EqualFold(p.Escrow,GuestEscrow) ||
 !strings.EqualFold(p.Token,"0x9e851bf5e3b613aaa09853a07d1132f49c90b515") || p.Mode!="couch" ||
 !strings.EqualFold(p.Operator,m.Operator) || p.Minutes<1 || p.Minutes>60 || p.Rate<=0 || p.Minimum!=60 || seconds>p.Minutes*60 {
 return fmt.Errorf("couch terms identity or duration")
 }
 cap:=new(big.Int).Mul(big.NewInt(p.Rate),big.NewInt(p.Minutes*60))
 if cap.BitLen()>256 || cap.String()!=p.Cap {return fmt.Errorf("couch terms cap")}
 return nil
}

func (m *Meter) CouchClaim(t CouchTerms, seconds, used int64) (GuestClaim,error) {
 if err:=m.ValidateCouchTerms(t,seconds);err!=nil {return GuestClaim{},err}
 if used<0 || used>seconds {return GuestClaim{},fmt.Errorf("couch usage exceeds grant")}
 var p couchPrice
 if err:=json.Unmarshal([]byte(t.Terms),&p);err!=nil {return GuestClaim{},err}
 billed:=used
 if billed>0 && billed<p.Minimum {billed=p.Minimum}
 owed:=new(big.Int).Mul(big.NewInt(p.Rate),big.NewInt(billed))
 return m.SignGuestClaim(t.Buyer,t.TermsHash,owed.String())
}
