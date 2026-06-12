package testharness

import (
	"math/rand/v2"

	"github.com/islishude/tss"
)

// NetworkConfig describes the fault injection configuration for a protocol run.
// Each predicate returns true when the corresponding fault should be applied
// to the given envelope.
type NetworkConfig struct {
	// Drop returns true to drop the message entirely.
	Drop func(env tss.Envelope) bool
	// Duplicate returns true to deliver the message twice.
	Duplicate func(env tss.Envelope) bool
	// Reorder shuffles the delivery order within the batch.
	Reorder bool
	// Mutate transforms the envelope before delivery. Applied after
	// drop/duplicate decisions.
	Mutate MutateFn
}

// DeliverMessages applies the configured faults and returns the set of messages
// that would be delivered. The optional rng is used for shuffle when Reorder
// is true.
func DeliverMessages(msgs []tss.Envelope, cfg NetworkConfig, rng *rand.Rand) []tss.Envelope {
	var out []tss.Envelope
	for _, env := range msgs {
		if cfg.Drop != nil && cfg.Drop(env) {
			continue
		}
		delivered := env
		if cfg.Mutate != nil {
			delivered = cfg.Mutate(delivered)
		}
		out = append(out, delivered)
		if cfg.Duplicate != nil && cfg.Duplicate(env) {
			dup := env
			if cfg.Mutate != nil {
				dup = cfg.Mutate(dup)
			}
			out = append(out, dup)
		}
	}
	if cfg.Reorder && rng != nil {
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out
}
