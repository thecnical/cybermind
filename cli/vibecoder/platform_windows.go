//go:build windows

package vibecoder

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

// NormalizePath normalizes a path for Windows (forward slashes → backslashes,
// drive letter handling).
func NormalizePath(p string) string {
	return filepath.FromSlash(p)
}

// DefaultShell returns the default shell command and args for Windows.
// Prefers PowerShell if available, falls back to cmd.exe.
func DefaultShell() (string, []string) {
	// Check for PowerShell
	if _, err := exec.LookPath("powershell.exe"); err == nil {
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command"}
	}
	return "cmd.exe", []string{"/C"}
}

// IsWSLAvailable returns true if WSL is available on this Windows system.
func IsWSLAvailable() bool {
	_, err := exec.LookPath("wsl.exe")
	return err == nil
}

// EnableVirtualTerminalProcessing enables ANSI escape code support in the
// Windows console. This is a no-op on Windows 10+ where it's enabled by default
// via the Go runtime, but we call it explicitly for older systems.
func EnableVirtualTerminalProcessing() error {
	// Go's os package handles this automatically on Windows 10+.
	// This function exists as a hook for future explicit enablement if needed.
	return nil
}

// atomicWriteConfig writes data to path atomically (temp file + rename)
// and sets owner-only ACL via icacls.
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
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite: rename: %w", err)
	}

	// Set owner-only ACL
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("atomicWrite: get current user: %w", err)
	}
	username := u.Username
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", username+":F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("atomicWrite: icacls: %w: %s", err, out)
	}
	return nil
}
