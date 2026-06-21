package secp256k1

import "github.com/islishude/tss"

type preparedPresignStart struct {
	session   *PresignSession
	out       []tss.Envelope
	committed bool
}

func (p *preparedPresignStart) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.session != nil {
		p.session.abort()
	}
	for i := range p.out {
		clear(p.out[i].Payload)
	}
}

func (p *preparedPresignStart) markCommitted() {
	if p != nil {
		p.committed = true
	}
}
