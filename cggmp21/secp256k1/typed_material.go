package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
	pai "github.com/islishude/tss/internal/paillier"
	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// paillierPublicMaterial is the typed in-memory representation of one
// participant's Paillier public key and modulus proof.
type paillierPublicMaterial struct {
	Party     tss.PartyID
	PublicKey *pai.PublicKey
	Proof     *zkpai.ModulusProof
}

// ringPedersenPublicMaterial is the typed in-memory representation of one
// participant's Ring-Pedersen parameters and proof.
type ringPedersenPublicMaterial struct {
	Party  tss.PartyID
	Params *zkpai.RingPedersenParams
	Proof  *zkpai.RingPedersenProof
}

func (m paillierPublicMaterial) snapshot(limits Limits) (PaillierPublicShare, error) {
	if m.Party == tss.BroadcastPartyId {
		return PaillierPublicShare{}, errors.New("paillier public material: zero party")
	}
	publicKey, err := canonicalWireMessageBytes(m.PublicKey, limits)
	if err != nil {
		return PaillierPublicShare{}, fmt.Errorf("paillier public material key: %w", err)
	}
	proof, err := canonicalWireMessageBytes(m.Proof, limits)
	if err != nil {
		return PaillierPublicShare{}, fmt.Errorf("paillier public material proof: %w", err)
	}
	return PaillierPublicShare{
		Party:     m.Party,
		PublicKey: publicKey,
		Proof:     proof,
	}, nil
}

func paillierPublicMaterialFromSnapshot(in PaillierPublicShare, limits Limits) (paillierPublicMaterial, error) {
	if err := in.ValidateWithLimits(limits); err != nil {
		return paillierPublicMaterial{}, err
	}
	publicKey, err := pai.UnmarshalPublicKeyWithMaxModulusBits(in.PublicKey, limits.Paillier.MaxModulusBits)
	if err != nil {
		return paillierPublicMaterial{}, fmt.Errorf("paillier public material key: %w", err)
	}
	proof, err := zkpai.UnmarshalModulusProof(in.Proof)
	if err != nil {
		return paillierPublicMaterial{}, fmt.Errorf("paillier public material proof: %w", err)
	}
	return paillierPublicMaterial{
		Party:     in.Party,
		PublicKey: publicKey,
		Proof:     proof,
	}, nil
}

func (m ringPedersenPublicMaterial) snapshot(limits Limits) (RingPedersenPublicShare, error) {
	if m.Party == tss.BroadcastPartyId {
		return RingPedersenPublicShare{}, errors.New("Ring-Pedersen public material: zero party")
	}
	params, err := canonicalWireMessageBytes(m.Params, limits)
	if err != nil {
		return RingPedersenPublicShare{}, fmt.Errorf("Ring-Pedersen public material params: %w", err)
	}
	proof, err := canonicalWireMessageBytes(m.Proof, limits)
	if err != nil {
		return RingPedersenPublicShare{}, fmt.Errorf("Ring-Pedersen public material proof: %w", err)
	}
	return RingPedersenPublicShare{
		Party:  m.Party,
		Params: params,
		Proof:  proof,
	}, nil
}

func ringPedersenPublicMaterialFromSnapshot(in RingPedersenPublicShare, limits Limits) (ringPedersenPublicMaterial, error) {
	if err := in.ValidateWithLimits(limits); err != nil {
		return ringPedersenPublicMaterial{}, err
	}
	params, err := zkpai.UnmarshalRingPedersenParamsWithMaxModulusBits(in.Params, limits.Paillier.MaxModulusBits)
	if err != nil {
		return ringPedersenPublicMaterial{}, fmt.Errorf("Ring-Pedersen public material params: %w", err)
	}
	proof, err := zkpai.UnmarshalRingPedersenProof(in.Proof)
	if err != nil {
		return ringPedersenPublicMaterial{}, fmt.Errorf("Ring-Pedersen public material proof: %w", err)
	}
	return ringPedersenPublicMaterial{
		Party:  in.Party,
		Params: params,
		Proof:  proof,
	}, nil
}
