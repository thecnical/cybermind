package vibecoder

// Feature: cybermind-vibe-coder, Property 16: File Indexer Non-Binary Exclusion
// Binary files (containing null bytes) must be excluded from indexing.
// Text files must be indexed and searchable.
// Validates: Requirements 20.1

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBinary_TextFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.go")
	if err := os.WriteFile(path, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isBinary(path) {
		t.Error("isBinary returned true for a text file")
	}
}

func TestIsBinary_BinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	// Write bytes with a null byte
	data := []byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0x0d, 0x0a, 0x1a}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if !isBinary(path) {
		t.Error("isBinary returned false for a binary file containing null byte")
	}
}

// Property 16: FileIndexer must include text files and exclude binary files.
func TestFileIndexer_NonBinaryExclusion(t *testing.T) {
	dir := t.TempDir()

	// Create a text file
	textPath := filepath.Join(dir, "main.go")
	textContent := "package main\n\nfunc hello() string {\n\treturn \"hello world\"\n}\n"
	if err := os.WriteFile(textPath, []byte(textContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a binary file
	binPath := filepath.Join(dir, "image.bin")
	binData := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0xFF}
	if err := os.WriteFile(binPath, binData, 0o644); err != nil {
		t.Fatal(err)
	}

	indexer := NewFileIndexer(dir, "", nil)

	// Index both files
	if err := indexer.IndexFile(textPath); err != nil {
		t.Fatalf("IndexFile(text) error: %v", err)
	}
	if err := indexer.IndexFile(binPath); err != nil {
		t.Fatalf("IndexFile(binary) error: %v", err)
	}

	// Search for content from the text file
	results, err := indexer.Search("hello world", 10)
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}

	// Text file should be indexed
	found := false
	for _, r := range results {
		if r.FilePath == textPath {
			found = true
			break
		}
	}
	if !found {
		t.Error("text file was not indexed (not found in search results)")
	}

	// Binary file should NOT be in the index at all
	indexer.index.mu.RLock()
	for _, e := range indexer.index.entries {
		if e.FilePath == binPath {
			indexer.index.mu.RUnlock()
			t.Error("binary file was indexed but should have been excluded")
			return
		}
	}
	indexer.index.mu.RUnlock()
}

func TestChunkText_SingleChunk(t *testing.T) {
	text := "package main\n\nfunc main() {}\n"
	chunks := chunkText(text, "main.go")
	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}
	if chunks[0].FilePath != "main.go" {
		t.Errorf("FilePath = %q, want %q", chunks[0].FilePath, "main.go")
	}
	// The chunk text should contain all the original content.
	// (strings.Split on a trailing newline produces an extra empty element,
	// so the chunk may have one extra trailing newline — that's acceptable.)
	if !containsStr(chunks[0].Text, "package main") || !containsStr(chunks[0].Text, "func main()") {
		t.Errorf("chunk text missing expected content, got: %q", chunks[0].Text)
	}
}

func TestChunkText_MultipleChunks(t *testing.T) {
	// Build a text larger than 2048 chars
	var sb []byte
	for i := 0; i < 100; i++ {
		sb = append(sb, []byte("// This is a line of Go code that is used to test chunking behavior.\n")...)
	}
	text := string(sb)
	chunks := chunkText(text, "big.go")
	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks for large text, got %d", len(chunks))
	}
	// All chunks should reference the same file
	for _, c := range chunks {
		if c.FilePath != "big.go" {
			t.Errorf("chunk FilePath = %q, want %q", c.FilePath, "big.go")
		}
	}
}

func TestVectorIndex_AddAndSearch(t *testing.T) {
	idx := &VectorIndex{}

	e1 := IndexEntry{FilePath: "a.go", Text: "hello", Embedding: []float32{1, 0, 0}}
	e2 := IndexEntry{FilePath: "b.go", Text: "world", Embedding: []float32{0, 1, 0}}
	idx.Add(e1)
	idx.Add(e2)

	query := []float32{1, 0, 0}
	results := idx.Search(query, 1)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].FilePath != "a.go" {
		t.Errorf("top result = %q, want %q", results[0].FilePath, "a.go")
	}
}

func TestVectorIndex_RemoveFile(t *testing.T) {
	idx := &VectorIndex{}
	idx.Add(IndexEntry{FilePath: "a.go", Embedding: []float32{1, 0}})
	idx.Add(IndexEntry{FilePath: "b.go", Embedding: []float32{0, 1}})
	idx.RemoveFile("a.go")

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	for _, e := range idx.entries {
		if e.FilePath == "a.go" {
			t.Error("a.go should have been removed from index")
		}
	}
}

func TestLoadIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	gitignore := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(gitignore, []byte("*.log\n# comment\nnode_modules\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	indexer := NewFileIndexer(dir, "", nil)
	indexer.LoadIgnorePatterns()

	indexer.mu.RLock()
	patterns := indexer.ignorePatterns
	indexer.mu.RUnlock()

	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns (comments excluded), got %d: %v", len(patterns), patterns)
	}
}

func TestTFIDFEmbedder_Embed(t *testing.T) {
	e := &TFIDFEmbedder{}
	vec, err := e.Embed("hello world hello")
	if err != nil {
		t.Fatalf("Embed error: %v", err)
	}
	if len(vec) != 256 {
		t.Errorf("expected 256-dim vector, got %d", len(vec))
	}
	// Should be unit vector (normalized)
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("vector not normalized: magnitude^2 = %f", sum)
	}
}
