package sessiontx

import (
	"reflect"
	"testing"
)

func TestCleanupStackLIFOAndDisarm(t *testing.T) {
	t.Parallel()

	var calls []int
	cleanup := NewCleanupStack()
	cleanup.Add(func() { calls = append(calls, 1) })
	cleanup.Add(func() { calls = append(calls, 2) })
	cleanup.Run()
	cleanup.Run()
	if want := []int{2, 1}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup calls = %v, want %v", calls, want)
	}

	disarmed := NewCleanupStack()
	disarmed.Add(func() { calls = append(calls, 3) })
	disarmed.Disarm()
	disarmed.Run()
	if want := []int{2, 1}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("disarmed cleanup calls = %v, want %v", calls, want)
	}
}
