package mta

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	secp "github.com/islishude/tss/internal/curve/secp256k1"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

type StartMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	EncProof   []byte `json:"enc_proof"`
	RangeProof []byte `json:"range_proof"`
}

type ResponseMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Proof      []byte `json:"proof"`
}

func Start(reader io.Reader, domain []byte, a *big.Int, pk *pai.PublicKey) (*StartMessage, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if a == nil || a.Sign() <= 0 || a.Cmp(secp.Order()) >= 0 {
		return nil, errors.New("a out of range")
	}
	c, r, err := pk.Encrypt(reader, a)
	if err != nil {
		return nil, err
	}
	encProof, rangeProof, err := zkpai.ProveEncScalarAndRange(reader, domain, pk, c, a, r)
	if err != nil {
		return nil, err
	}
	encProofBytes, err := zkpai.Marshal(encProof)
	if err != nil {
		return nil, err
	}
	rangeProofBytes, err := zkpai.Marshal(rangeProof)
	if err != nil {
		return nil, err
	}
	return &StartMessage{Ciphertext: c.Bytes(), EncProof: encProofBytes, RangeProof: rangeProofBytes}, nil
}

func VerifyStart(domain []byte, msg StartMessage, pk *pai.PublicKey) bool {
	c := new(big.Int).SetBytes(msg.Ciphertext)
	encProof, err := zkpai.UnmarshalEncScalarProof(msg.EncProof)
	if err != nil {
		return false
	}
	rangeProof, err := zkpai.UnmarshalEncRangeProof(msg.RangeProof)
	if err != nil {
		return false
	}
	return zkpai.VerifyEncScalarAndRange(domain, pk, c, encProof, rangeProof)
}

func Respond(reader io.Reader, startDomain, responseDomain []byte, start StartMessage, b *big.Int, bCommitment []byte, pkA *pai.PublicKey) (*ResponseMessage, *big.Int, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if !VerifyStart(startDomain, start, pkA) {
		return nil, nil, errors.New("invalid MtA start proof")
	}
	if b == nil || b.Sign() <= 0 || b.Cmp(secp.Order()) >= 0 {
		return nil, nil, errors.New("b out of range")
	}
	encA := new(big.Int).SetBytes(start.Ciphertext)
	beta, err := randomScalar(reader)
	if err != nil {
		return nil, nil, err
	}
	encBeta, betaRandomness, err := pkA.Encrypt(reader, beta)
	if err != nil {
		return nil, nil, err
	}
	response := new(big.Int).Exp(encA, b, pkA.NSquared)
	response.Mul(response, encBeta)
	response.Mod(response, pkA.NSquared)
	proof, err := zkpai.ProveMTAResponse(reader, responseDomain, pkA, encA, response, bCommitment, b, beta, betaRandomness)
	if err != nil {
		return nil, nil, err
	}
	proofBytes, err := zkpai.Marshal(proof)
	if err != nil {
		return nil, nil, err
	}
	betaShare := new(big.Int).Neg(beta)
	betaShare.Mod(betaShare, secp.Order())
	return &ResponseMessage{Ciphertext: response.Bytes(), Proof: proofBytes}, betaShare, nil
}

func Finish(startDomain, responseDomain []byte, start StartMessage, response ResponseMessage, bCommitment []byte, skA *pai.PrivateKey) (*big.Int, error) {
	if skA == nil {
		return nil, errors.New("nil Paillier private key")
	}
	if !VerifyStart(startDomain, start, &skA.PublicKey) {
		return nil, errors.New("invalid MtA start proof")
	}
	proof, err := zkpai.UnmarshalMTAResponseProof(response.Proof)
	if err != nil {
		return nil, err
	}
	encA := new(big.Int).SetBytes(start.Ciphertext)
	resp := new(big.Int).SetBytes(response.Ciphertext)
	if !zkpai.VerifyMTAResponse(responseDomain, &skA.PublicKey, encA, resp, bCommitment, proof) {
		return nil, fmt.Errorf("invalid MtA response proof")
	}
	alpha, err := skA.Decrypt(resp)
	if err != nil {
		return nil, err
	}
	alpha.Mod(alpha, secp.Order())
	return alpha, nil
}

func randomScalar(reader io.Reader) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, secp.Order())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}
