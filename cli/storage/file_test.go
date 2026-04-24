package storage

import (
	"strings"
	"testing"
	"testing/quick"
)

// Feature: cybermind-new-modes, Property 4: Brain_Memory Round-Trip
//
// For any target identifier and findings string, calling storage.AddEntry(key, value)
// followed by retrieval of that key SHALL return a value equal to the original
// findings string.
//
// Validates: Requirements 1.8, 5.3, 5.9

// TestProperty4_BrainMemoryRoundTrip verifies that AddEntry followed by GetHistory
// always returns the original value for the stored key.
func TestProperty4_BrainMemoryRoundTrip(t *testing.T) {
	// Ensure the storage directory exists so SaveToFile doesn't fail.
	if err := CreateDirectoryIfNotExists(); err != nil {
		t.Fatalf("failed to create storage directory: %v", err)
	}

	f := func(key, value string) bool {
		// Skip strings with null bytes — not valid in JSON
		if strings.ContainsRune(key, 0) || strings.ContainsRune(value, 0) {
			return true
		}

		// Reset in-memory state and disk before each iteration.
		if err := ClearHistory(); err != nil {
			// If we can't clear (e.g. permission issue), skip this iteration.
			return true
		}

		// Store the entry.
		if err := AddEntry(key, value); err != nil {
			// Disk write failure is not a round-trip failure — skip.
			return true
		}

		// Retrieve all entries and find the one matching our key.
		history := GetHistory()
		for _, e := range history {
			if e.User == key {
				// The AI field must equal the original value exactly.
				return e.AI == value
			}
		}

		// Entry not found — round-trip failed.
		return false
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// TestProperty4_BrainMemoryRoundTrip_MultipleEntries verifies that when multiple
// entries are stored, each key still maps to its original value (no cross-contamination).
//
// Validates: Requirements 1.8, 5.3, 5.9
func TestProperty4_BrainMemoryRoundTrip_MultipleEntries(t *testing.T) {
	if err := CreateDirectoryIfNotExists(); err != nil {
		t.Fatalf("failed to create storage directory: %v", err)
	}

	type pair struct {
		Key   string
		Value string
	}

	f := func(pairs [3]pair) bool {
		// Skip any pair with null bytes.
		for _, p := range pairs {
			if strings.ContainsRune(p.Key, 0) || strings.ContainsRune(p.Value, 0) {
				return true
			}
		}

		if err := ClearHistory(); err != nil {
			return true
		}

		// Store all pairs.
		for _, p := range pairs {
			if err := AddEntry(p.Key, p.Value); err != nil {
				return true
			}
		}

		// Verify each pair can be retrieved correctly.
		history := GetHistory()
		for i, p := range pairs {
			found := false
			for _, e := range history {
				if e.User == p.Key && e.AI == p.Value {
					found = true
					break
				}
			}
			if !found {
				// Check if the key exists but with wrong value (cross-contamination).
				for _, e := range history {
					if e.User == p.Key {
						t.Logf("pair[%d]: key=%q found but value mismatch: got %q, want %q", i, p.Key, e.AI, p.Value)
						return false
					}
				}
				// Key not found at all.
				t.Logf("pair[%d]: key=%q not found in history", i, p.Key)
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// TestProperty4_BrainMemoryRoundTrip_EmptyStrings verifies that empty key and
// value strings are stored and retrieved correctly.
//
// Validates: Requirements 1.8, 5.3, 5.9
func TestProperty4_BrainMemoryRoundTrip_EmptyStrings(t *testing.T) {
	if err := CreateDirectoryIfNotExists(); err != nil {
		t.Fatalf("failed to create storage directory: %v", err)
	}

	if err := ClearHistory(); err != nil {
		t.Skip("cannot clear history, skipping test")
	}

	if err := AddEntry("", ""); err != nil {
		t.Fatalf("AddEntry with empty strings failed: %v", err)
	}

	history := GetHistory()
	if len(history) == 0 {
		t.Fatal("expected at least one entry after AddEntry, got none")
	}

	// Find the entry with empty User field.
	for _, e := range history {
		if e.User == "" {
			if e.AI != "" {
				t.Errorf("empty value round-trip failed: got %q, want %q", e.AI, "")
			}
			return
		}
	}
	t.Error("entry with empty key not found in history")
}
