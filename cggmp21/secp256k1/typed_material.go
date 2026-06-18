package secp256k1

import (
	"errors"
	"fmt"
	"math/big"

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

func cloneBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func clonePaillierPublicKey(pk *pai.PublicKey) *pai.PublicKey {
	if pk == nil {
		return nil
	}
	return &pai.PublicKey{
		N:        cloneBigInt(pk.N),
		G:        cloneBigInt(pk.G),
		NSquared: cloneBigInt(pk.NSquared),
	}
}

func cloneRingPedersenParams(params *zkpai.RingPedersenParams) *zkpai.RingPedersenParams {
	if params == nil {
		return nil
	}
	return &zkpai.RingPedersenParams{
		N: cloneBigInt(params.N),
		S: cloneBigInt(params.S),
		T: cloneBigInt(params.T),
	}
}

func (m paillierPublicMaterial) clone() paillierPublicMaterial {
	return paillierPublicMaterial{
		Party:     m.Party,
		PublicKey: clonePaillierPublicKey(m.PublicKey),
		Proof:     m.Proof.Clone(),
	}
}

func (m ringPedersenPublicMaterial) clone() ringPedersenPublicMaterial {
	return ringPedersenPublicMaterial{
		Party:  m.Party,
		Params: cloneRingPedersenParams(m.Params),
		Proof:  m.Proof.Clone(),
	}
}

func clonePaillierPublicMaterials(in []paillierPublicMaterial) []paillierPublicMaterial {
	if in == nil {
		return nil
	}
	out := make([]paillierPublicMaterial, len(in))
	for i := range in {
		out[i] = in[i].clone()
	}
	return out
}

func cloneRingPedersenPublicMaterials(in []ringPedersenPublicMaterial) []ringPedersenPublicMaterial {
	if in == nil {
		return nil
	}
	out := make([]ringPedersenPublicMaterial, len(in))
	for i := range in {
		out[i] = in[i].clone()
	}
	return out
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

func paillierPublicMaterialSnapshots(in []paillierPublicMaterial, limits Limits) ([]PaillierPublicShare, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]PaillierPublicShare, len(in))
	for i := range in {
		snapshot, err := in[i].snapshot(limits)
		if err != nil {
			return nil, fmt.Errorf("paillier public material %d: %w", i, err)
		}
		out[i] = snapshot
	}
	return out, nil
}

func paillierPublicMaterialsFromSnapshots(in []PaillierPublicShare, limits Limits) ([]paillierPublicMaterial, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]paillierPublicMaterial, len(in))
	for i := range in {
		material, err := paillierPublicMaterialFromSnapshot(in[i], limits)
		if err != nil {
			return nil, fmt.Errorf("paillier public material %d: %w", i, err)
		}
		out[i] = material
	}
	return out, nil
}

func ringPedersenPublicMaterialSnapshots(in []ringPedersenPublicMaterial, limits Limits) ([]RingPedersenPublicShare, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]RingPedersenPublicShare, len(in))
	for i := range in {
		snapshot, err := in[i].snapshot(limits)
		if err != nil {
			return nil, fmt.Errorf("Ring-Pedersen public material %d: %w", i, err)
		}
		out[i] = snapshot
	}
	return out, nil
}

func ringPedersenPublicMaterialsFromSnapshots(in []RingPedersenPublicShare, limits Limits) ([]ringPedersenPublicMaterial, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]ringPedersenPublicMaterial, len(in))
	for i := range in {
		material, err := ringPedersenPublicMaterialFromSnapshot(in[i], limits)
		if err != nil {
			return nil, fmt.Errorf("Ring-Pedersen public material %d: %w", i, err)
		}
		out[i] = material
	}
	return out, nil
}
