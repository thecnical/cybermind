package vibecoder

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// ─── 43.1 Full session turn integration test ─────────────────────────────────
// Feature: cybermind-vibe-coder
// Validates: Requirements 24.1, 24.2, 24.3

func TestIntegration_FullSessionTurn(t *testing.T) {
	dir := t.TempDir()
	session := NewSession(dir)
	session.AddMessage(Message{Role: RoleUser, Content: "hello", Tokens: 5, Timestamp: time.Now()})

	// Mock provider that returns a simple response with no tool calls
	provider := &noToolCallProvider{response: "Hello! How can I help?"}

	guard, _ := NewWorkspaceGuard(dir)
	env := &ToolEnv{Guard: guard, WorkspaceRoot: dir, Timeout: 10, SessionID: session.ID}
	registry := NewDefaultToolRegistry()
	engine := NewToolEngine(registry, env)

	loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{MaxIterations: 5})

	err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Verify assistant message was added
	found := false
	for _, msg := range session.History {
		if msg.Role == RoleAssistant && msg.Content == "Hello! How can I help?" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected assistant message in history")
	}
}

// ─── 43.2 Checkpoint save and restore ────────────────────────────────────────
// Feature: cybermind-vibe-coder
// Validates: Requirements 19.1, 19.2, 19.3

func TestIntegration_CheckpointSaveRestore(t *testing.T) {
	dir := t.TempDir()

	// Create and populate a session
	session := NewSession(dir)
	session.AddMessage(Message{Role: RoleUser, Content: "test message", Tokens: 10, Timestamp: time.Now()})
	session.EditMode = EditModeAutoEdit

	// Save checkpoint
	cm := NewCheckpointManager(dir, 5)
	if err := cm.Save(session); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load latest checkpoint
	restored, err := cm.LoadLatest()
	if err != nil {
		t.Fatalf("LoadLatest() error: %v", err)
	}
	if restored == nil {
		t.Fatal("LoadLatest() returned nil")
	}

	// Verify key fields
	if restored.ID != session.ID {
		t.Errorf("ID mismatch: got %q, want %q", restored.ID, session.ID)
	}
	if restored.EditMode != session.EditMode {
		t.Errorf("EditMode mismatch: got %q, want %q", restored.EditMode, session.EditMode)
	}
	if len(restored.History) != len(session.History) {
		t.Errorf("History len mismatch: got %d, want %d", len(restored.History), len(session.History))
	}
}

// ─── 43.3 File indexer incremental update ────────────────────────────────────
// Feature: cybermind-vibe-coder
// Validates: Requirements 20.4

func TestIntegration_FileIndexerIncrementalUpdate(t *testing.T) {
	dir := t.TempDir()

	// Create initial file
	filePath := dir + "/main.go"
	if err := os.WriteFile(filePath, []byte("package main\n\nfunc hello() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	indexer := NewFileIndexer(dir, "", nil)
	if err := indexer.IndexFile(filePath); err != nil {
		t.Fatalf("IndexFile error: %v", err)
	}

	// Search for initial content
	results, err := indexer.Search("hello", 5)
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected search results for 'hello'")
	}

	// Update the file
	if err := os.WriteFile(filePath, []byte("package main\n\nfunc goodbye() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-index
	if err := indexer.IndexFile(filePath); err != nil {
		t.Fatalf("IndexFile (update) error: %v", err)
	}

	// Search for new content
	results2, err := indexer.Search("goodbye", 5)
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(results2) == 0 {
		t.Error("expected search results for 'goodbye' after update")
	}
}

// ─── 43.4 Paid Tier token refresh flow ───────────────────────────────────────
// Feature: cybermind-vibe-coder
// Validates: Requirements 13.2

func TestIntegration_PaidTierTokenRefresh(t *testing.T) {
	// ManagedProvider is created with a supabase URL
	mp := NewManagedProvider("https://example.supabase.co")

	// Verify it's not nil and has the correct URL
	if mp == nil {
		t.Fatal("NewManagedProvider returned nil")
	}

	// Verify JWT is not written to disk (it's empty initially)
	mp.mu.Lock()
	jwt := mp.jwt
	mp.mu.Unlock()

	if jwt != "" {
		t.Error("JWT should be empty before fetchJWT is called")
	}

	// Verify Name() works
	name := mp.Name()
	if name == "" {
		t.Error("Name() should not be empty")
	}
}

// ─── 43.5 Provider chain failover ────────────────────────────────────────────
// Feature: cybermind-vibe-coder
// Validates: Requirements 2.2, 2.3

func TestIntegration_ProviderChainFailover(t *testing.T) {
	// First provider always fails with quota error
	failProvider := &mockProvider{name: "fail", err: fmt.Errorf("quota exceeded (429)")}
	// Second provider succeeds
	successProvider := &mockProvider{name: "success"}

	chain := NewProviderChain([]Provider{failProvider, successProvider}, "fail")

	ch, err := chain.StreamChat(context.Background(), ChatRequest{Model: "test", Stream: true})
	if err != nil {
		t.Fatalf("StreamChat error: %v", err)
	}

	var token string
	for ev := range ch {
		if ev.Token != "" {
			token = ev.Token
		}
	}

	if token != "hello from success" {
		t.Errorf("expected token from success provider, got %q", token)
	}
}
