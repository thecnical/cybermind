package vibecoder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Property 11: Conversation History Preservation
// Feature: cybermind-vibe-coder
// Validates: Requirements 9.1
//
// For any sequence of AddMessage calls, the session history must:
//  1. Preserve all messages in order
//  2. Correctly accumulate token counts
//  3. Return the 90% warning at the right threshold

func TestSessionAddMessage_HistoryPreservation(t *testing.T) {
	messages := []Message{
		{Role: RoleUser, Content: "hello", Tokens: 10, Timestamp: time.Now()},
		{Role: RoleAssistant, Content: "world", Tokens: 20, Timestamp: time.Now()},
		{Role: RoleUser, Content: "foo", Tokens: 5, Timestamp: time.Now()},
	}

	s := NewSession("/workspace")
	for _, msg := range messages {
		s.AddMessage(msg)
	}

	// Property 1: all messages preserved in order
	if len(s.History) != len(messages) {
		t.Fatalf("expected %d messages, got %d", len(messages), len(s.History))
	}
	for i, msg := range messages {
		if s.History[i].Content != msg.Content {
			t.Errorf("message[%d] content = %q, want %q", i, s.History[i].Content, msg.Content)
		}
		if s.History[i].Role != msg.Role {
			t.Errorf("message[%d] role = %q, want %q", i, s.History[i].Role, msg.Role)
		}
	}

	// Property 2: token accumulation is correct
	wantTokens := 10 + 20 + 5
	if s.TokensUsed != wantTokens {
		t.Errorf("TokensUsed = %d, want %d", s.TokensUsed, wantTokens)
	}
}

func TestSessionAddMessage_90PercentWarning(t *testing.T) {
	tests := []struct {
		name      string
		maxTokens int
		tokens    int
		wantWarn  bool
	}{
		{"below threshold", 1000, 800, false},
		{"exactly at threshold", 1000, 900, true},
		{"above threshold", 1000, 950, true},
		{"at 100%", 1000, 1000, true},
		{"over 100%", 1000, 1100, true},
		{"zero tokens", 1000, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSession("/workspace")
			s.MaxTokens = tc.maxTokens
			msg := Message{Role: RoleUser, Content: "test", Tokens: tc.tokens}
			warned := s.AddMessage(msg)
			if warned != tc.wantWarn {
				t.Errorf("AddMessage warning = %v, want %v (tokens=%d, max=%d)",
					warned, tc.wantWarn, tc.tokens, tc.maxTokens)
			}
		})
	}
}

func TestSessionContextUsagePercent(t *testing.T) {
	tests := []struct {
		name      string
		maxTokens int
		used      int
		wantPct   float64
	}{
		{"zero max", 0, 0, 0},
		{"zero used", 1000, 0, 0},
		{"50%", 1000, 500, 50.0},
		{"90%", 1000, 900, 90.0},
		{"100%", 1000, 1000, 100.0},
		{"over 100% capped", 1000, 1500, 100.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSession("/workspace")
			s.MaxTokens = tc.maxTokens
			s.TokensUsed = tc.used
			got := s.ContextUsagePercent()
			if got != tc.wantPct {
				t.Errorf("ContextUsagePercent() = %v, want %v", got, tc.wantPct)
			}
		})
	}
}

func TestSessionUndoStack(t *testing.T) {
	s := NewSession("/workspace")

	// Empty stack returns false
	_, ok := s.PopUndo()
	if ok {
		t.Error("PopUndo on empty stack should return false")
	}

	snaps := []FileSnapshot{
		{Path: "a.go", OldContent: "content a"},
		{Path: "b.go", OldContent: "content b"},
		{Path: "c.go", OldContent: "content c"},
	}

	for _, snap := range snaps {
		s.PushUndo(snap)
	}

	// Pop in LIFO order
	for i := len(snaps) - 1; i >= 0; i-- {
		got, ok := s.PopUndo()
		if !ok {
			t.Fatalf("PopUndo returned false at index %d", i)
		}
		if got.Path != snaps[i].Path {
			t.Errorf("PopUndo path = %q, want %q", got.Path, snaps[i].Path)
		}
		if got.OldContent != snaps[i].OldContent {
			t.Errorf("PopUndo content = %q, want %q", got.OldContent, snaps[i].OldContent)
		}
	}

	// Stack should be empty now
	_, ok = s.PopUndo()
	if ok {
		t.Error("PopUndo should return false after all items popped")
	}
}

// Property 12: Session Serialization Round-Trip
// Feature: cybermind-vibe-coder
// Validates: Requirements 9.3, 19.3
//
// SaveHistory must produce valid JSON that can be deserialized back to a Session.
// The deserialized session must have the same ID, WorkspaceRoot, and message count.
// File contents must be omitted in the saved JSON.

func TestSessionSaveHistory_RoundTrip(t *testing.T) {
	// Use a temp dir as home to avoid writing to real home
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome) // Windows

	s := NewSession("/my/workspace")
	s.History = []Message{
		{Role: RoleUser, Content: "hello", Tokens: 5, Timestamp: time.Now()},
		{Role: RoleAssistant, Content: "world", Tokens: 10, Timestamp: time.Now()},
	}
	s.OpenFiles = map[string]FileEntry{
		"main.go": {
			Path:    "main.go",
			Content: "package main\n\nfunc main() {}",
			Hash:    "abc123",
			AddedAt: time.Now(),
		},
	}
	s.UndoStack = []FileSnapshot{
		{Path: "old.go", OldContent: "old content"},
	}

	if err := s.SaveHistory(); err != nil {
		t.Fatalf("SaveHistory() error: %v", err)
	}

	// Find the saved file
	histDir := filepath.Join(tmpHome, ".cybermind", "vibe_history")
	entries, err := os.ReadDir(histDir)
	if err != nil {
		t.Fatalf("ReadDir(%q) error: %v", histDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 history file, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(histDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Must be valid JSON
	var restored Session
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	// ID and WorkspaceRoot preserved
	if restored.ID != s.ID {
		t.Errorf("ID = %q, want %q", restored.ID, s.ID)
	}
	if restored.WorkspaceRoot != s.WorkspaceRoot {
		t.Errorf("WorkspaceRoot = %q, want %q", restored.WorkspaceRoot, s.WorkspaceRoot)
	}

	// Message count preserved
	if len(restored.History) != len(s.History) {
		t.Errorf("History len = %d, want %d", len(restored.History), len(s.History))
	}

	// File contents must be omitted (sanitized)
	for path, fe := range restored.OpenFiles {
		if fe.Content != "" {
			t.Errorf("OpenFiles[%q].Content should be empty, got %q", path, fe.Content)
		}
		// Path and Hash should be preserved
		orig := s.OpenFiles[path]
		if fe.Path != orig.Path {
			t.Errorf("OpenFiles[%q].Path = %q, want %q", path, fe.Path, orig.Path)
		}
		if fe.Hash != orig.Hash {
			t.Errorf("OpenFiles[%q].Hash = %q, want %q", path, fe.Hash, orig.Hash)
		}
	}

	// UndoStack content must be omitted
	for i, snap := range restored.UndoStack {
		if snap.OldContent != "" {
			t.Errorf("UndoStack[%d].OldContent should be empty, got %q", i, snap.OldContent)
		}
		if snap.Path != s.UndoStack[i].Path {
			t.Errorf("UndoStack[%d].Path = %q, want %q", i, snap.Path, s.UndoStack[i].Path)
		}
	}
}

func TestNewSession_Defaults(t *testing.T) {
	s := NewSession("/some/path")

	if s.ID == "" {
		t.Error("ID should not be empty")
	}
	if s.WorkspaceRoot != "/some/path" {
		t.Errorf("WorkspaceRoot = %q, want %q", s.WorkspaceRoot, "/some/path")
	}
	if s.EditMode != EditModeGuard {
		t.Errorf("EditMode = %q, want %q", s.EditMode, EditModeGuard)
	}
	if s.InteractMode != InteractModeAgent {
		t.Errorf("InteractMode = %q, want %q", s.InteractMode, InteractModeAgent)
	}
	if s.EffortLevel != EffortMedium {
		t.Errorf("EffortLevel = %q, want %q", s.EffortLevel, EffortMedium)
	}
	if s.MaxTokens != 128000 {
		t.Errorf("MaxTokens = %d, want 128000", s.MaxTokens)
	}
	if s.History == nil {
		t.Error("History should be initialized (not nil)")
	}
	if s.OpenFiles == nil {
		t.Error("OpenFiles should be initialized (not nil)")
	}
	if s.UndoStack == nil {
		t.Error("UndoStack should be initialized (not nil)")
	}
	if s.DebugMode {
		t.Error("DebugMode should default to false")
	}
}

func TestGenerateUUID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateUUID()
		if id == "" {
			t.Fatal("generateUUID returned empty string")
		}
		if seen[id] {
			t.Fatalf("generateUUID returned duplicate: %q", id)
		}
		seen[id] = true
	}
}
