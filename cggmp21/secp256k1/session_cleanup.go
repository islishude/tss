package secp256k1

type cleanupStack struct {
	fns   []func()
	armed bool
}

func newCleanupStack() *cleanupStack {
	return &cleanupStack{armed: true}
}

func (c *cleanupStack) Add(fn func()) {
	if c == nil || fn == nil {
		return
	}
	c.fns = append(c.fns, fn)
}

func (c *cleanupStack) Disarm() {
	if c == nil {
		return
	}
	c.armed = false
}

func (c *cleanupStack) Run() {
	if c == nil || !c.armed {
		return
	}
	c.armed = false
	for i := len(c.fns) - 1; i >= 0; i-- {
		c.fns[i]()
	}
}
