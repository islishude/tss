package secp256k1

import "testing"

func TestPresignSessionCompletedDoesNotTransferPresign(t *testing.T) {
	p := minimalCGGMP21Presign(t)
	session := &PresignSession{
		completed: true,
		presign:   p,
	}

	if !session.Completed() {
		t.Fatal("completed presign session reported incomplete on first check")
	}
	if !session.Completed() {
		t.Fatal("completed presign session reported incomplete on repeated check")
	}
	if session.presign != p || session.presignReturned {
		t.Fatal("Completed transferred the session-owned presign")
	}

	got, ok := session.Presign()
	if !ok || got != p {
		t.Fatal("Presign did not transfer the completed record after status checks")
	}
}
