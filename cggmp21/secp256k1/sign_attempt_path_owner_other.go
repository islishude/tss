//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package secp256k1

import "io/fs"

// FileMode does not expose sufficient ownership/ACL information on these
// platforms, so the reference file store fails closed instead of claiming a
// path-replacement guarantee it cannot establish.
func signAttemptStoreTrustedOwner(fs.FileInfo) bool { return false }
