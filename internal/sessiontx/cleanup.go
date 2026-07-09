package sessiontx

import "slices"

// CleanupStack runs cleanup callbacks in reverse registration order unless
// disarmed after ownership has been committed.
type CleanupStack struct {
	callbacks []func()
	armed     bool
}

// NewCleanupStack returns an armed cleanup stack.
func NewCleanupStack() *CleanupStack {
	return &CleanupStack{armed: true}
}

// Add registers fn to run during cleanup.
func (c *CleanupStack) Add(fn func()) {
	if c == nil || !c.armed || fn == nil {
		return
	}
	c.callbacks = append(c.callbacks, fn)
}

// Disarm prevents registered cleanup callbacks from running.
func (c *CleanupStack) Disarm() {
	if c == nil {
		return
	}
	c.armed = false
	c.callbacks = nil
}

// Run executes cleanup callbacks at most once in LIFO order.
func (c *CleanupStack) Run() {
	if c == nil || !c.armed {
		return
	}
	c.armed = false
	for _, v := range slices.Backward(c.callbacks) {
		v()
	}
	c.callbacks = nil
}
