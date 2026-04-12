package vibecoder

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// makeTestEnv creates a ToolEnv backed by a temp directory.
func makeTestEnv(t *testing.T) (*ToolEnv, string) {
	t.Helper()
	dir := t.TempDir()
	guard, err := NewWorkspaceGuard(dir)
	if err != nil {
		t.Fatalf("NewWorkspaceGuard: %v", err)
	}
	return &ToolEnv{
		Guard:         guard,
		WorkspaceRoot: dir,
		NoExec:        false,
		Timeout:       10,
		SessionID:     "test-session",
	}, dir
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// ─── Property 4: File Read Round-Trip ─────────────────────────────────────────
// Write a file, read it back — content must match.
// Validates: Requirements 3.1

func TestToolProperty4_FileReadRoundTrip(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		content string
	}{
		{"simple text", "hello world"},
		{"multiline", "line1\nline2\nline3"},
		{"empty", ""},
		{"unicode", "こんにちは 🌍"},
		{"binary-like", "\x01\x02\x03 data"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relPath := "testfile.txt"
			absPath := filepath.Join(dir, relPath)

			// Write directly.
			if err := os.WriteFile(absPath, []byte(tc.content), 0644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			// Read via tool.
			tool := &ReadFileTool{}
			result, err := tool.Execute(ctx, mustJSON(map[string]any{"path": relPath}), env)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.Error != "" {
				t.Fatalf("tool error: %s", result.Error)
			}
			if result.Output != tc.content {
				t.Errorf("content mismatch: got %q, want %q", result.Output, tc.content)
			}
		})
	}
}

// ─── Property 5: Diff Always Precedes Write ───────────────────────────────────
// WriteFileTool must compute SHA-256 before and verify after write.
// Validates: Requirements 3.5

func TestToolProperty5_WriteFileSHA256BeforeAndAfter(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	contents := []string{
		"simple content",
		"multiline\ncontent\nhere",
		strings.Repeat("x", 1000),
	}

	for i, content := range contents {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			relPath := fmt.Sprintf("file_%d.txt", i)
			absPath := filepath.Join(dir, relPath)

			tool := &WriteFileTool{}
			result, err := tool.Execute(ctx, mustJSON(map[string]any{
				"path":    relPath,
				"content": content,
			}), env)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.Error != "" {
				t.Fatalf("tool error: %s", result.Error)
			}

			// Verify the file was actually written with correct content.
			data, err := os.ReadFile(absPath)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(data) != content {
				t.Errorf("written content mismatch")
			}

			// Verify SHA-256 of written file matches expected.
			expectedHash := sha256sumBytes([]byte(content))
			actualHash, err := sha256sum(absPath)
			if err != nil {
				t.Fatalf("sha256sum: %v", err)
			}
			if expectedHash != actualHash {
				t.Errorf("SHA-256 mismatch: expected %s, got %s", expectedHash, actualHash)
			}
		})
	}
}

// ─── Property 6: Atomic Write Correctness ────────────────────────────────────
// WriteFileTool must not leave partial files on error.
// Validates: Requirements 3.5

func TestToolProperty6_AtomicWriteCorrectness(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	// Write initial content.
	relPath := "atomic_test.txt"
	absPath := filepath.Join(dir, relPath)
	initial := "initial content"
	if err := os.WriteFile(absPath, []byte(initial), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Write new content via tool.
	newContent := "new content after atomic write"
	tool := &WriteFileTool{}
	result, err := tool.Execute(ctx, mustJSON(map[string]any{
		"path":    relPath,
		"content": newContent,
	}), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("tool error: %s", result.Error)
	}

	// File must contain the new content (not partial).
	data, err := os.ReadFile(absPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != newContent {
		t.Errorf("expected %q, got %q", newContent, string(data))
	}

	// No temp files should remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vibecoder-atomic-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// ─── Property 7: Undo Round-Trip ─────────────────────────────────────────────
// PushUndo + PopUndo must restore original content.
// Validates: Requirements 3.6

func TestToolProperty7_UndoRoundTrip(t *testing.T) {
	_, dir := makeTestEnv(t)

	session := NewSession(dir)

	cases := []struct {
		path    string
		content string
	}{
		{"file_a.txt", "original content A"},
		{"file_b.txt", "original content B"},
		{"nested/file_c.txt", "original content C"},
	}

	// Push snapshots.
	for _, tc := range cases {
		session.PushUndo(FileSnapshot{Path: tc.path, OldContent: tc.content})
	}

	// Pop and verify LIFO order.
	for i := len(cases) - 1; i >= 0; i-- {
		snap, ok := session.PopUndo()
		if !ok {
			t.Fatalf("PopUndo returned false at index %d", i)
		}
		if snap.Path != cases[i].path {
			t.Errorf("path mismatch: got %q, want %q", snap.Path, cases[i].path)
		}
		if snap.OldContent != cases[i].content {
			t.Errorf("content mismatch: got %q, want %q", snap.OldContent, cases[i].content)
		}
	}

	// Stack should be empty now.
	_, ok := session.PopUndo()
	if ok {
		t.Error("expected empty undo stack")
	}
}

// ─── Property 9: Search Results Workspace Containment ────────────────────────
// GrepSearch results must all be within workspace.
// Validates: Requirements 4.1

func TestToolProperty9_GrepSearchWorkspaceContainment(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	// Create some files with known content.
	files := map[string]string{
		"a.txt":        "hello world",
		"sub/b.txt":    "hello from sub",
		"sub/c.go":     "package main // hello",
		"other/d.txt":  "no match here",
	}
	for rel, content := range files {
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(abs, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	tool := &GrepSearchTool{}
	result, err := tool.Execute(ctx, mustJSON(map[string]any{"pattern": "hello"}), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("tool error: %s", result.Error)
	}

	// Every result line must start with a path inside the workspace.
	// Format: /path/to/file:lineNo: content  (Unix)
	//      or C:\path\to\file:lineNo: content (Windows)
	// We extract the file path by finding the last colon that is followed by
	// digits (the line number), which avoids confusing Windows drive letters.
	lineNoRe := regexp.MustCompile(`^(.+):(\d+):`)
	for _, line := range strings.Split(result.Output, "\n") {
		if line == "" || strings.HasPrefix(line, "[results") {
			continue
		}
		m := lineNoRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		matchPath := m[1]
		if !strings.HasPrefix(matchPath, dir) {
			t.Errorf("result path %q is outside workspace %q", matchPath, dir)
		}
	}
}

// ─── Property 20: Tool Schema Validation ─────────────────────────────────────
// All registered tools must have valid JSON schemas.
// Validates: Requirements 5.1

func TestToolProperty20_AllToolSchemasValid(t *testing.T) {
	registry := NewDefaultToolRegistry()
	for _, tool := range registry.All() {
		t.Run(tool.Name(), func(t *testing.T) {
			schema := tool.Schema()
			if len(schema) == 0 {
				t.Errorf("tool %q has empty schema", tool.Name())
				return
			}
			if !json.Valid(schema) {
				t.Errorf("tool %q has invalid JSON schema: %s", tool.Name(), string(schema))
				return
			}
			// Must be a JSON object.
			var obj map[string]any
			if err := json.Unmarshal(schema, &obj); err != nil {
				t.Errorf("tool %q schema is not a JSON object: %v", tool.Name(), err)
			}
		})
	}
}

// ─── Property 23: TodoWrite Single In-Progress Invariant ─────────────────────
// TodoWriteTool must reject >1 in_progress.
// Validates: Requirements 6.1

func TestToolProperty23_TodoWriteSingleInProgressInvariant(t *testing.T) {
	env, _ := makeTestEnv(t)
	ctx := context.Background()
	tool := &TodoWriteTool{}

	t.Run("zero in_progress is allowed", func(t *testing.T) {
		todos := []TodoItem{
			{ID: "1", Content: "task 1", Status: "pending"},
			{ID: "2", Content: "task 2", Status: "done"},
		}
		result, err := tool.Execute(ctx, mustJSON(map[string]any{"todos": todos}), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Error != "" {
			t.Fatalf("unexpected tool error: %s", result.Error)
		}
	})

	t.Run("exactly one in_progress is allowed", func(t *testing.T) {
		todos := []TodoItem{
			{ID: "1", Content: "task 1", Status: "pending"},
			{ID: "2", Content: "task 2", Status: "in_progress"},
			{ID: "3", Content: "task 3", Status: "done"},
		}
		result, err := tool.Execute(ctx, mustJSON(map[string]any{"todos": todos}), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Error != "" {
			t.Fatalf("unexpected tool error: %s", result.Error)
		}
	})

	t.Run("two in_progress is rejected", func(t *testing.T) {
		todos := []TodoItem{
			{ID: "1", Content: "task 1", Status: "in_progress"},
			{ID: "2", Content: "task 2", Status: "in_progress"},
		}
		_, err := tool.Execute(ctx, mustJSON(map[string]any{"todos": todos}), env)
		if err == nil {
			t.Error("expected error for two in_progress todos, got nil")
		}
	})

	t.Run("three in_progress is rejected", func(t *testing.T) {
		todos := []TodoItem{
			{ID: "1", Content: "task 1", Status: "in_progress"},
			{ID: "2", Content: "task 2", Status: "in_progress"},
			{ID: "3", Content: "task 3", Status: "in_progress"},
		}
		_, err := tool.Execute(ctx, mustJSON(map[string]any{"todos": todos}), env)
		if err == nil {
			t.Error("expected error for three in_progress todos, got nil")
		}
	})
}

// ─── Property 25: Write Verification Integrity ────────────────────────────────
// WriteFileTool SHA-256 must match after write.
// Validates: Requirements 3.5

func TestToolProperty25_WriteVerificationIntegrity(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	payloads := []string{
		"",
		"a",
		strings.Repeat("hello\n", 100),
		"unicode: 日本語テスト",
		strings.Repeat("z", 10000),
	}

	for i, content := range payloads {
		t.Run(fmt.Sprintf("payload_%d", i), func(t *testing.T) {
			relPath := fmt.Sprintf("verify_%d.txt", i)
			absPath := filepath.Join(dir, relPath)

			tool := &WriteFileTool{}
			result, err := tool.Execute(ctx, mustJSON(map[string]any{
				"path":    relPath,
				"content": content,
			}), env)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.Error != "" {
				t.Fatalf("tool error: %s", result.Error)
			}

			// Independently verify SHA-256.
			data, err := os.ReadFile(absPath)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			expectedHash := sha256sumBytes([]byte(content))
			actualHash := sha256sumBytes(data)
			if expectedHash != actualHash {
				t.Errorf("SHA-256 integrity failure: expected %s, got %s", expectedHash, actualHash)
			}
		})
	}
}

// ─── Additional: EditFileTool basic correctness ───────────────────────────────

func TestToolEditFile(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	relPath := "edit_me.txt"
	absPath := filepath.Join(dir, relPath)
	original := "foo bar baz"
	if err := os.WriteFile(absPath, []byte(original), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tool := &EditFileTool{}
	result, err := tool.Execute(ctx, mustJSON(map[string]any{
		"path":        relPath,
		"old_content": "bar",
		"new_content": "qux",
	}), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("tool error: %s", result.Error)
	}

	data, _ := os.ReadFile(absPath)
	if string(data) != "foo qux baz" {
		t.Errorf("expected %q, got %q", "foo qux baz", string(data))
	}
}

// ─── Additional: ToolEngine.Execute unknown tool ──────────────────────────────

func TestToolEngineUnknownTool(t *testing.T) {
	env, _ := makeTestEnv(t)
	registry := NewDefaultToolRegistry()
	engine := NewToolEngine(registry, env)

	result := engine.Execute(context.Background(), ToolCall{
		ID:     "x",
		Name:   "nonexistent_tool",
		Params: json.RawMessage(`{}`),
	})
	if result.Error == "" {
		t.Error("expected error for unknown tool")
	}
}

// ─── Additional: ToolEngine.Execute invalid JSON params ───────────────────────

func TestToolEngineInvalidParams(t *testing.T) {
	env, _ := makeTestEnv(t)
	registry := NewDefaultToolRegistry()
	engine := NewToolEngine(registry, env)

	result := engine.Execute(context.Background(), ToolCall{
		ID:     "y",
		Name:   "read_file",
		Params: json.RawMessage(`not-valid-json`),
	})
	if result.Error == "" {
		t.Error("expected error for invalid JSON params")
	}
}

// ─── Additional: GlobSearch within workspace ─────────────────────────────────

func TestToolGlobSearch(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	// Create some .txt files.
	for _, name := range []string{"a.txt", "b.txt", "c.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	tool := &GlobSearchTool{}
	result, err := tool.Execute(ctx, mustJSON(map[string]any{"pattern": "*.txt"}), env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("tool error: %s", result.Error)
	}

	// Should find a.txt and b.txt but not c.go.
	if !strings.Contains(result.Output, "a.txt") {
		t.Error("expected a.txt in results")
	}
	if !strings.Contains(result.Output, "b.txt") {
		t.Error("expected b.txt in results")
	}
	if strings.Contains(result.Output, "c.go") {
		t.Error("c.go should not appear in *.txt glob")
	}
}

// ─── Additional: RunCommandTool NoExec ───────────────────────────────────────

func TestToolRunCommandNoExec(t *testing.T) {
	env, _ := makeTestEnv(t)
	env.NoExec = true
	ctx := context.Background()

	tool := &RunCommandTool{}
	_, err := tool.Execute(ctx, mustJSON(map[string]any{"command": "echo hello"}), env)
	if err == nil {
		t.Error("expected error when NoExec=true")
	}
}

// ─── Additional: RunCommandTool blocked command ───────────────────────────────

func TestToolRunCommandBlocked(t *testing.T) {
	env, _ := makeTestEnv(t)
	ctx := context.Background()

	tool := &RunCommandTool{}
	_, err := tool.Execute(ctx, mustJSON(map[string]any{"command": "rm -rf /"}), env)
	if err == nil {
		t.Error("expected error for blocked command")
	}
}

// ─── Additional: CreateFolder and DeleteFile ──────────────────────────────────

func TestToolCreateFolderAndDeleteFile(t *testing.T) {
	env, dir := makeTestEnv(t)
	ctx := context.Background()

	// Create folder.
	folderTool := &CreateFolderTool{}
	result, err := folderTool.Execute(ctx, mustJSON(map[string]any{"path": "newdir/sub"}), env)
	if err != nil {
		t.Fatalf("CreateFolder Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("CreateFolder error: %s", result.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "newdir/sub")); err != nil {
		t.Errorf("folder not created: %v", err)
	}

	// Create a file then delete it.
	createTool := &CreateFileTool{}
	_, err = createTool.Execute(ctx, mustJSON(map[string]any{"path": "todelete.txt", "content": "bye"}), env)
	if err != nil {
		t.Fatalf("CreateFile Execute: %v", err)
	}

	deleteTool := &DeleteFileTool{}
	result, err = deleteTool.Execute(ctx, mustJSON(map[string]any{"path": "todelete.txt"}), env)
	if err != nil {
		t.Fatalf("DeleteFile Execute: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("DeleteFile error: %s", result.Error)
	}
	if _, err := os.Stat(filepath.Join(dir, "todelete.txt")); !os.IsNotExist(err) {
		t.Error("file should have been deleted")
	}
}
