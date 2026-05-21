package tss

type SensitiveBytes []byte

func (s SensitiveBytes) Destroy() {
	for i := range s {
		s[i] = 0
	}
}

func CloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
