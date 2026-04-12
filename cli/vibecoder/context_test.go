package vibecoder

// Feature: cybermind-vibe-coder, Property 22: Context Budget Invariant
// The sum of all context budget percentages must equal 1.0 (100%).
// CompressContext must reduce TokensUsed after compression.
// Validates: Requirements (context budget allocation)

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContextBudget_SumEqualsOne verifies that the default context budget
// percentages sum to exactly 1.0 (100%).
func TestContextBudget_SumEqualsOne(t *testing.T) {
	b := DefaultContextBudget
	sum := b.ConversationPct + b.MemoryPct + b.SemanticPct + b.PinnedPct
	if sum < 0.9999 || sum > 1.0001 {
		t.Errorf("ContextBudget percentages sum = %f, want 1.0 (conversation=%.2f memory=%.2f semantic=%.2f pinned=%.2f)",
			sum, b.ConversationPct, b.MemoryPct, b.SemanticPct, b.PinnedPct)
	}
}

// TestCompressContext_ReducesTokensUsed verifies that CompressContext reduces
// TokensUsed to only the tokens in the retained messages.
func TestCompressContext_ReducesTokensUsed(t *testing.T) {
	dir := t.TempDir()
	memory := NewCyberMindMemory(dir)

	s := NewSession(dir)
	// Add 10 messages with known token counts
	for i := 0; i < 10; i++ {
		s.AddMessage(Message{
			Role:    RoleUser,
			Content: "message",
			Tokens:  100,
		})
	}
	tokensBefore := s.TokensUsed // 1000

	CompressContext(s, memory)

	// After compression, only last 6 messages remain (600 tokens)
	if s.TokensUsed >= tokensBefore {
		t.Errorf("TokensUsed after compression = %d, should be less than %d", s.TokensUsed, tokensBefore)
	}
	if len(s.History) != 6 {
		t.Errorf("History len after compression = %d, want 6", len(s.History))
	}
	if s.TokensUsed != 600 {
		t.Errorf("TokensUsed = %d, want 600", s.TokensUsed)
	}
}

// TestCompressContext_NoOpWhenFewMessages verifies that CompressContext does
// nothing when there are fewer than 6 messages.
func TestCompressContext_NoOpWhenFewMessages(t *testing.T) {
	dir := t.TempDir()
	memory := NewCyberMindMemory(dir)

	s := NewSession(dir)
	for i := 0; i < 5; i++ {
		s.AddMessage(Message{Role: RoleUser, Content: "msg", Tokens: 10})
	}
	tokensBefore := s.TokensUsed
	histLenBefore := len(s.History)

	CompressContext(s, memory)

	if s.TokensUsed != tokensBefore {
		t.Errorf("TokensUsed changed from %d to %d (should be no-op)", tokensBefore, s.TokensUsed)
	}
	if len(s.History) != histLenBefore {
		t.Errorf("History len changed from %d to %d (should be no-op)", histLenBefore, len(s.History))
	}
}

// TestCyberMindMemory_SaveAndLoad verifies round-trip save/load.
func TestCyberMindMemory_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	memory := NewCyberMindMemory(dir)

	content := "# CYBERMIND.md\n\nTest content\n"
	if err := memory.Save(content); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	loaded := memory.Load()
	if loaded != content {
		t.Errorf("Load() = %q, want %q", loaded, content)
	}
}

// TestCyberMindMemory_LoadMissing verifies that Load returns "" when file doesn't exist.
func TestCyberMindMemory_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	memory := NewCyberMindMemory(dir)

	result := memory.Load()
	if result != "" {
		t.Errorf("Load() on missing file = %q, want empty string", result)
	}
}

// TestCyberMindMemory_Init verifies that Init creates a CYBERMIND.md file.
func TestCyberMindMemory_Init(t *testing.T) {
	dir := t.TempDir()
	// Create a go.mod to trigger Go detection
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	memory := NewCyberMindMemory(dir)
	content, err := memory.Init(dir)
	if err != nil {
		t.Fatalf("Init error: %v", err)
	}

	if content == "" {
		t.Error("Init returned empty content")
	}

	// File should exist
	if _, err := os.Stat(filepath.Join(dir, "CYBERMIND.md")); err != nil {
		t.Errorf("CYBERMIND.md not created: %v", err)
	}

	// Should detect Go module
	if !contains(content, "Go module") {
		t.Errorf("Init content should mention 'Go module', got: %s", content)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
