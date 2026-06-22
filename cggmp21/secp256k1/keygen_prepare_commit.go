package secp256k1

import (
	"github.com/islishude/tss"
	secp "github.com/islishude/tss/internal/curve/secp256k1"
	"github.com/islishude/tss/internal/shamir"
)

type preparedCGGMPKeygenStart struct {
	session   *KeygenSession
	out       []tss.Envelope
	committed bool
}

func (p *preparedCGGMPKeygenStart) destroy() {
	if p == nil || p.committed {
		return
	}
	if p.session != nil {
		p.session.abort()
		if p.session.keyShare != nil {
			p.session.keyShare.Destroy()
		}
	}
	for i := range p.out {
		clear(p.out[i].Payload)
	}
}

func (p *preparedCGGMPKeygenStart) markCommitted() {
	if p != nil {
		p.committed = true
	}
}

func clearSecpPolynomial(poly shamir.Polynomial) {
	for i := range poly {
		poly[i] = secp.ScalarZero()
	}
}
