//go:build !windows

package vibecoder

import (
	"fmt"
	"os"
	"path/filepath"
)

// NormalizePath returns the path unchanged on Unix (already POSIX).
func NormalizePath(p string) string {
	return p
}

// DefaultShell returns the user's default shell from $SHELL.
// Falls back to /bin/bash (Linux) or /bin/zsh (macOS).
func DefaultShell() (string, []string) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		// Prefer bash on Linux, zsh on macOS
		if _, err := os.Stat("/bin/bash"); err == nil {
			shell = "/bin/bash"
		} else {
			shell = "/bin/sh"
		}
	}
	return shell, []string{"-c"}
}

// IsWSLAvailable always returns false on Unix.
func IsWSLAvailable() bool {
	return false
}

// EnableVirtualTerminalProcessing is a no-op on Unix.
func EnableVirtualTerminalProcessing() error {
	return nil
}

// atomicWriteConfig writes data to path atomically (temp file + rename)
// and sets owner-only permissions (0600).
func atomicWriteConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vibecoder-tmp-*")
	if err != nil {
		return fmt.Errorf("atomicWrite: create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite: rename: %w", err)
	}
	return nil
}
