//go:build integration || vectorgen

package secp256k1

type cggmp21TestVector struct {
	Description    string          `json:"description"`
	Threshold      int             `json:"threshold"`
	N              int             `json:"n"`
	Parties        []int           `json:"parties"`
	Seed           string          `json:"seed"`
	GroupPublicKey string          `json:"group_public_key"`
	KeygenShares   []string        `json:"keygen_shares"`
	Presigns       []string        `json:"presigns"`
	Digest         string          `json:"digest"`
	Signature      *cggmpSigVector `json:"signature"`
}

type cggmpSigVector struct {
	R string `json:"r"`
	S string `json:"s"`
}
