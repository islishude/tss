package ed25519

import "github.com/islishude/tss"

func (s *SignSession) tryEmitPartial() ([]tss.Envelope, error) {
	prepared, ok, err := s.prepareLocalPartial()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	defer prepared.destroy()
	effects := s.commitLocalPartial(prepared)
	if err := s.tryAggregate(); err != nil {
		return nil, err
	}
	return effects.envelopes, nil
}
