//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package secp256k1

import (
	"io/fs"
	"os"
	"syscall"
)

func signAttemptStoreTrustedOwner(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := uint32(os.Geteuid())
	return stat.Uid == 0 || stat.Uid == uid
}
