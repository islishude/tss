// Package testvectors provides shared helpers for reading, locating, and
// validating the repository's committed test-vector files.
package testvectors

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var dirOnce = sync.OnceValues(func() (string, error) {
	if override := os.Getenv("TSS_TESTVECTORS_DIR"); override != "" {
		dir, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolve TSS_TESTVECTORS_DIR: %w", err)
		}
		if err := validateDir(dir); err != nil {
			return "", err
		}
		return dir, nil
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	if !filepath.IsAbs(file) {
		return "", fmt.Errorf("testvectors source path is not absolute: %s", file)
	}

	dir := filepath.Dir(file)
	if err := validateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
})

// Dir returns the absolute filesystem path to the internal/testvectors source
// directory. It is intended for update/generation code that must write committed
// vector files; normal verification should use Read.
func Dir() (string, error) {
	return dirOnce()
}

// Path returns an absolute filesystem path under internal/testvectors for
// update/generation code that must write committed vector files.
func Path(name string) (string, error) {
	clean, err := cleanName(name)
	if err != nil {
		return "", err
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.FromSlash(clean)), nil
}

func validateDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("testvectors directory is not absolute: %s", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		return fmt.Errorf("testvectors directory sanity check: %w", err)
	}
	return nil
}

func cleanName(name string) (string, error) {
	clean := path.Clean(name)
	if name == "" || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "./") || path.IsAbs(name) {
		return "", fmt.Errorf("invalid test vector path %q", name)
	}
	if strings.HasPrefix(clean, ".") || strings.Contains(clean, "/.") || strings.Contains(clean, "\\") || strings.Contains(clean, ":") {
		return "", fmt.Errorf("invalid test vector path %q", name)
	}
	return clean, nil
}
