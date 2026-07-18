package tss

import "slices"

// SignRequest is a context-bound message supplied for signature creation or
// verification. Protocols decide how the context and message are hashed.
type SignRequest struct {
	Context SigningContext `json:"context"`
	Message []byte         `json:"message"`
}

// Clone returns an independently owned copy of the signing request.
func (r SignRequest) Clone() SignRequest {
	return SignRequest{
		Context: r.Context.Clone(),
		Message: slices.Clone(r.Message),
	}
}

// SignIntent is the protocol-independent shared intent that signers authorize
// before producing protocol messages.
type SignIntent struct {
	SessionID SessionID
	Context   SigningContext
	Message   []byte
	Signers   PartySet
}

// Clone returns an independently owned copy of the signing intent.
func (i SignIntent) Clone() SignIntent {
	return SignIntent{
		SessionID: i.SessionID,
		Context:   i.Context.Clone(),
		Message:   slices.Clone(i.Message),
		Signers:   i.Signers.Clone(),
	}
}

// Request returns the context-bound request represented by the intent.
func (i SignIntent) Request() SignRequest {
	return SignRequest{
		Context: i.Context.Clone(),
		Message: slices.Clone(i.Message),
	}
}
