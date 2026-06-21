package ed25519

import "github.com/islishude/tss"

type preparedKeygenStart struct {
	session   *KeygenSession
	out       []tss.Envelope
	committed bool
}

func (p *preparedKeygenStart) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.session != nil {
		p.session.abort()
		if p.session.keyShare != nil {
			p.session.keyShare.Destroy()
		}
	}
	clearEnvelopePayloads(p.out)
}

func (p *preparedKeygenStart) markCommitted() {
	if p != nil {
		p.committed = true
	}
}
