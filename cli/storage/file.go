package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// getStoragePath returns the path to ~/.cybermind/history.json (cross-platform)
func getStoragePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cybermind")
	return filepath.Join(dir, "history.json"), nil
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

// SaveToFile writes entries to the JSON history file with secure permissions
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
	// 0600 — only owner can read/write history (contains sensitive chat data)
	return os.WriteFile(path, data, 0600)
}

// ReadFromFile loads entries from the JSON history file
func ReadFromFile() ([]Entry, error) {
	path, err := getStoragePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil // no history yet, not an error
		}
		return nil, err
	}

	if len(data) == 0 {
		return []Entry{}, nil
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		// Corrupted JSON — return empty rather than crash
		return []Entry{}, nil
	}
	return entries, nil
}
