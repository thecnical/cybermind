package vibecoder

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// atomicWrite writes data to path atomically using a temp file in the same
// directory (guarantees same-volume rename on Windows).
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vibecoder-atomic-*")
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
	return nil
}

// sha256sum returns the hex-encoded SHA-256 hash of the file at path.
func sha256sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// sha256sumBytes returns the hex-encoded SHA-256 hash of data.
func sha256sumBytes(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

// estimateTokens returns a rough token count estimate for text.
// Uses the heuristic: 1 token ≈ 4 characters for English text.
func estimateTokens(text string) int {
	if text == "" {
		return 0
	}
	chars := utf8.RuneCountInString(text)
	tokens := chars / 4
	if tokens == 0 {
		tokens = 1
	}
	return tokens
}

// EstimateTokensPublic is the exported version of estimateTokens for use by the tui package.
func EstimateTokensPublic(text string) int {
	return estimateTokens(text)
}

// truncateOutput truncates s to maxChars, appending a truncation notice.
func truncateOutput(s string, maxChars int) (string, bool) {
	if len(s) <= maxChars {
		return s, false
	}
	return s[:maxChars] + "\n[output truncated]", true
}

// containsNullByte returns true if s contains a null byte.
func containsNullByte(s string) bool {
	return strings.ContainsRune(s, '\x00')
}
