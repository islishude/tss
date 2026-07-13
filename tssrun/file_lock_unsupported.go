//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package tssrun

import (
	"context"
	"errors"
	"os"
)

var errFileLifecycleLockUnsupported = errors.New("tssrun: OS advisory file locks are unsupported on this platform")

func lockFileContext(context.Context, *os.File) error {
	return errFileLifecycleLockUnsupported
}

func unlockFile(*os.File) error { return nil }
