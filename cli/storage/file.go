package storage

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// getStoragePath returns the path to ~/.cybermind/history.json (cross-platform)
func getStoragePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cybermind")
	return filepath.Join(dir, "history.enc"), nil
}

// CreateDirectoryIfNotExists ensures ~/.cybermind/ exists with secure permissions
func CreateDirectoryIfNotExists() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".cybermind")
	// 0700 — only owner can access the directory
	return os.MkdirAll(dir, 0700)
}

// deriveKey creates a machine-specific XOR key from hostname + username.
// This is obfuscation, not strong encryption — it prevents casual file reads
// but not a determined attacker with filesystem access.
// The key is deterministic so history survives reboots.
func deriveKey() []byte {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "cybermind"
	}
	// Add OS to make key platform-specific
	raw := hostname + ":" + username + ":" + runtime.GOOS + ":cybermind-history-v1"
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// xorEncrypt XORs data with a repeating key (symmetric — same function for encrypt/decrypt)
func xorEncrypt(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// SaveToFile writes entries to the encrypted history file with secure permissions
func SaveToFile(entries []Entry) error {
	if err := CreateDirectoryIfNotExists(); err != nil {
		return err
	}
	path, err := getStoragePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	// XOR-encrypt before writing
	encrypted := xorEncrypt(data, deriveKey())
	// 0600 — only owner can read/write history (contains sensitive chat data)
	return os.WriteFile(path, encrypted, 0600)
}

// ReadFromFile loads entries from the encrypted history file
func ReadFromFile() ([]Entry, error) {
	path, err := getStoragePath()
	if err != nil {
		return nil, err
	}

	// Try new encrypted path first
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Try legacy plaintext path for migration
			return readLegacyFile()
		}
		return nil, err
	}

	if len(data) == 0 {
		return []Entry{}, nil
	}

	// XOR-decrypt
	decrypted := xorEncrypt(data, deriveKey())

	var entries []Entry
	if err := json.Unmarshal(decrypted, &entries); err != nil {
		// Try plaintext fallback (in case file wasn't encrypted)
		if err2 := json.Unmarshal(data, &entries); err2 != nil {
			return []Entry{}, nil // corrupted — return empty
		}
	}
	return entries, nil
}

// readLegacyFile reads the old plaintext history.json and migrates to encrypted format
func readLegacyFile() ([]Entry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return []Entry{}, nil
	}
	legacyPath := filepath.Join(home, ".cybermind", "history.json")
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return []Entry{}, nil
	}
	if len(data) == 0 {
		return []Entry{}, nil
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return []Entry{}, nil
	}
	// Migrate: save as encrypted, remove plaintext
	if len(entries) > 0 {
		_ = SaveToFile(entries)
		_ = os.Remove(legacyPath)
	}
	return entries, nil
}
