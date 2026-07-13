package secp256k1

import (
	"errors"
	"fmt"

	"github.com/islishude/tss"
)

func isAuxInfoPayload(payload tss.PayloadType) bool {
	switch payload {
	case payloadAuxInfoCommitment, payloadAuxInfoReveal, payloadAuxInfoProofs, payloadAuxInfoDirect, payloadAuxInfoDecryptionError:
		return true
	default:
		return false
	}
}

func (s *ReshareSession) handleReshareAuxInfoInbound(in tss.InboundEnvelope, key paperKeygenMessageKey) ([]tss.Envelope, error) {
	env := in.Envelope()
	if !s.isReceiver {
		// Figure 7 broadcasts are addressed to the new committee but a transport
		// may fan them out to old dealer-only participants as well. Validate and
		// retire the authenticated envelope without interpreting its payload.
		if err := s.validateInbound(in, s.newParties); err != nil {
			return nil, err
		}
		s.accepted[key] = struct{}{}
		return nil, nil
	}
	if s.auxInfo == nil || s.newShare != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeRound, env.Round, env.From, errors.New("figure 7 message arrived outside the verified reshare handoff"))
	}
	prepared, err := s.auxInfo.prepareInbound(env)
	if err != nil {
		return nil, auxInfoPreparationError(env, s.newParties, err)
	}
	defer prepared.destroy()
	var output *preparedReshareOutput
	if prepared.result != nil {
		output, err = s.prepareReshareOutput(prepared.result)
		if err != nil {
			return nil, tss.NewProtocolError(tss.ErrCodeVerification, env.Round, env.From, err)
		}
		defer output.destroy()
	}
	if err := s.validateInbound(in, s.newParties); err != nil {
		return nil, err
	}
	if err := prepared.apply(); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, s.selfID, fmt.Errorf("commit reshare Figure 7 transition: %w", err))
	}
	s.accepted[key] = struct{}{}
	if prepared.failure != nil {
		s.terminalReshareFigure7Failure(prepared.failure)
		return prepared.out, nil
	}
	if output == nil {
		return prepared.out, nil
	}
	if err := s.commitReshareOutput(output); err != nil {
		return nil, tss.NewProtocolError(tss.ErrCodeInvariant, env.Round, s.selfID, err)
	}
	return append(prepared.out, output.confirmationEnvelope), nil
}

func (s *ReshareSession) terminalReshareFigure7Failure(failure *Figure7Failure) {
	s.abort()
	s.figure7Failure = cloneFigure7Failure(failure)
	// Completed is a terminal-disposition signal. KeyShare still distinguishes
	// this attributed failure from successful completion.
	s.completed = true
}

// Figure7Failure returns public-only attribution for a terminal reshare
// auxiliary-info failure.
func (s *ReshareSession) Figure7Failure() (Figure7Failure, bool) {
	if s == nil {
		return Figure7Failure{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.figure7Failure == nil {
		return Figure7Failure{}, false
	}
	return s.figure7Failure.Clone(), true
}
