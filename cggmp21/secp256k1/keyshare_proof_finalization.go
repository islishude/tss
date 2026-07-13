package secp256k1

import (
	"errors"
	"fmt"
	"io"

	zkpai "github.com/islishude/tss/internal/zk/paillier"
)

// finalizeSignReadyKeyShareProofs replaces the local party's Figure 7 modulus
// proof with a post-protocol proof bound to the complete sign-ready KeyShare.
//
// The Figure 7 transcript contains the broadcast and direct proofs, so those
// proofs cannot themselves include the final transcript hash without creating
// a Fiat-Shamir cycle. They instead bind the final EpochID and plan, and the
// transcript commits to their canonical encodings. This additional local proof
// is created only after that transcript is fixed and binds the resulting epoch,
// public key, transcript, lifecycle kind, and plan in one acyclic statement.
func finalizeSignReadyKeyShareProofs(reader io.Reader, share *KeyShare, limits Limits) error {
	if share == nil || share.state == nil {
		return errors.New("finalize sign-ready key-share proofs: nil key share")
	}
	if share.state.PaillierPrivateKey == nil {
		return errors.New("finalize sign-ready key-share proofs: missing local Paillier private key")
	}
	domain, err := keySharePaillierProofDomainWithLimits(share, limits)
	if err != nil {
		return fmt.Errorf("finalize sign-ready key-share modulus domain: %w", err)
	}
	proof, err := zkpai.ProveModulus(reader, domain, share.state.PaillierPrivateKey, share.state.Party)
	if err != nil {
		return fmt.Errorf("finalize sign-ready key-share modulus proof: %w", err)
	}
	data, err := share.partyDataFor(share.state.Party)
	if err != nil {
		proof.Destroy()
		return err
	}
	oldProof := data.PaillierProof
	data.PaillierProof = proof
	share.state.PartyData[share.state.Party] = data
	if oldProof != nil {
		oldProof.Destroy()
	}
	return nil
}
