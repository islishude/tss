package conformance

import (
	"testing"

	"github.com/islishude/tss/tssrun"
)

func TestMemoryImplementationsConform(t *testing.T) {
	RunConformance(t, Harness{
		NewRunStore: func(testing.TB) tssrun.RunStore {
			return tssrun.NewMemoryRunStore()
		},
		NewLifecycleStore: func(testing.TB) tssrun.LifecycleStore {
			return tssrun.NewMemoryLifecycleStore()
		},
		NewSessionRegistry: func(testing.TB) tssrun.SessionRegistry {
			return tssrun.NewMemorySessionRegistry()
		},
		NewUnknownStore: func(testing.TB) tssrun.UnknownEnvelopeStore {
			return tssrun.NewMemoryUnknownEnvelopeStore()
		},
	})
}
