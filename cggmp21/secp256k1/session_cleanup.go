package secp256k1

type cleanupStack struct {
	callbacks []func()
	armed     bool
}

func newCleanupStack() *cleanupStack {
	return &cleanupStack{armed: true}
}

func (c *cleanupStack) add(fn func()) {
	if c == nil || !c.armed || fn == nil {
		return
	}
	c.callbacks = append(c.callbacks, fn)
}

func (c *cleanupStack) disarm() {
	if c == nil {
		return
	}
	c.armed = false
	c.callbacks = nil
}

func (c *cleanupStack) run() {
	if c == nil || !c.armed {
		return
	}
	c.armed = false
	for i := len(c.callbacks) - 1; i >= 0; i-- {
		c.callbacks[i]()
	}
	c.callbacks = nil
}
