package vibecoder

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IndexEntry represents a single indexed chunk of a file.
type IndexEntry struct {
	FilePath  string    `json:"file_path"`
	ChunkIdx  int       `json:"chunk_idx"`
	StartLine int       `json:"start_line"`
	EndLine   int       `json:"end_line"`
	Embedding []float32 `json:"embedding"`
	Text      string    `json:"text"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Embedder produces a vector embedding for a text string.
type Embedder interface {
	Embed(text string) ([]float32, error)
}

// TFIDFEmbedder is a simple fallback embedder using term frequency.
type TFIDFEmbedder struct{}

func (e *TFIDFEmbedder) Embed(text string) ([]float32, error) {
	words := strings.Fields(strings.ToLower(text))
	freq := make(map[string]int)
	for _, w := range words {
		freq[w]++
	}
	// Use a fixed vocabulary size of 256 (hash-based)
	vec := make([]float32, 256)
	for w, count := range freq {
		idx := simpleHash(w) % 256
		vec[idx] += float32(count)
	}
	return normalize(vec), nil
}

func simpleHash(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func normalize(vec []float32) []float32 {
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum == 0 {
		return vec
	}
	mag := float32(math.Sqrt(sum))
	for i := range vec {
		vec[i] /= mag
	}
	return vec
}

// VectorIndex is an in-memory vector store.
type VectorIndex struct {
	entries []IndexEntry
	mu      sync.RWMutex
}

func (idx *VectorIndex) Add(entry IndexEntry) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries = append(idx.entries, entry)
}

func (idx *VectorIndex) RemoveFile(filePath string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	filtered := idx.entries[:0]
	for _, e := range idx.entries {
		if e.FilePath != filePath {
			filtered = append(filtered, e)
		}
	}
	idx.entries = filtered
}

// Search returns top-K entries by cosine similarity to query embedding.
func (idx *VectorIndex) Search(query []float32, k int) []IndexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	type scored struct {
		entry IndexEntry
		score float32
	}

	var results []scored
	for _, e := range idx.entries {
		score := cosineSimilarity(query, e.Embedding)
		results = append(results, scored{e, score})
	}

	// Sort by score descending (simple selection sort for small k)
	for i := 0; i < len(results) && i < k; i++ {
		maxIdx := i
		for j := i + 1; j < len(results); j++ {
			if results[j].score > results[maxIdx].score {
				maxIdx = j
			}
		}
		results[i], results[maxIdx] = results[maxIdx], results[i]
	}

	if k > len(results) {
		k = len(results)
	}
	out := make([]IndexEntry, k)
	for i := 0; i < k; i++ {
		out[i] = results[i].entry
	}
	return out
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var dot, magA, magB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		magA += float64(a[i]) * float64(a[i])
		magB += float64(b[i]) * float64(b[i])
	}
	if magA == 0 || magB == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(magA) * math.Sqrt(magB)))
}

// FileIndexer indexes workspace files and supports semantic search.
type FileIndexer struct {
	workspaceRoot  string
	indexPath      string
	embedder       Embedder
	index          *VectorIndex
	ignorePatterns []string
	mu             sync.RWMutex
	onProgress     func(done, total int)
	ready          bool
}

// NewFileIndexer creates a FileIndexer. If embedder is nil, TFIDFEmbedder is used.
func NewFileIndexer(workspaceRoot, indexPath string, embedder Embedder) *FileIndexer {
	if embedder == nil {
		embedder = &TFIDFEmbedder{}
	}
	return &FileIndexer{
		workspaceRoot: workspaceRoot,
		indexPath:     indexPath,
		embedder:      embedder,
		index:         &VectorIndex{},
	}
}

// chunkText splits text into overlapping chunks of ~512 tokens (≈2048 chars) with 64-token overlap (≈256 chars).
func chunkText(text string, filePath string) []IndexEntry {
	const chunkSize = 2048 // chars ≈ 512 tokens
	const overlap = 256   // chars ≈ 64 tokens

	lines := strings.Split(text, "\n")
	var chunks []IndexEntry

	var buf strings.Builder
	startLine := 1
	lineNo := 1
	charCount := 0
	chunkIdx := 0

	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteString("\n")
		charCount += len(line) + 1

		if charCount >= chunkSize {
			chunks = append(chunks, IndexEntry{
				FilePath:  filePath,
				ChunkIdx:  chunkIdx,
				StartLine: startLine,
				EndLine:   lineNo,
				Text:      buf.String(),
				UpdatedAt: time.Now(),
			})
			chunkIdx++

			// Overlap: keep last `overlap` chars
			t := buf.String()
			if len(t) > overlap {
				t = t[len(t)-overlap:]
			}
			buf.Reset()
			buf.WriteString(t)
			charCount = len(t)
			startLine = lineNo
		}
		lineNo++
	}

	// Last chunk
	if buf.Len() > 0 {
		chunks = append(chunks, IndexEntry{
			FilePath:  filePath,
			ChunkIdx:  chunkIdx,
			StartLine: startLine,
			EndLine:   lineNo - 1,
			Text:      buf.String(),
			UpdatedAt: time.Now(),
		})
	}

	return chunks
}

// isBinary returns true if the file appears to be binary (null byte in first 8192 bytes).
func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()

	buf := make([]byte, 8192)
	n, err := f.Read(buf)
	if err != nil {
		return false
	}
	return bytes.ContainsRune(buf[:n], 0)
}

// IndexFile indexes a single file.
func (fi *FileIndexer) IndexFile(path string) error {
	if isBinary(path) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fi.index.RemoveFile(path)
	chunks := chunkText(string(data), path)

	for i := range chunks {
		embedding, err := fi.embedder.Embed(chunks[i].Text)
		if err != nil {
			continue
		}
		chunks[i].Embedding = embedding
		fi.index.Add(chunks[i])
	}
	return nil
}

// Start begins background indexing of the workspace.
// Sends progress updates via onProgress callback.
// Uses polling (every 5 seconds) to detect file changes.
func (fi *FileIndexer) Start(onProgress func(done, total int)) {
	fi.onProgress = onProgress
	go fi.runIndexLoop()
}

func (fi *FileIndexer) runIndexLoop() {
	// Initial full index
	fi.fullIndex()

	fi.mu.Lock()
	fi.ready = true
	fi.mu.Unlock()

	// Poll for changes every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastMod := make(map[string]time.Time)

	for range ticker.C {
		_ = filepath.Walk(fi.workspaceRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if fi.isIgnored(path) {
				return nil
			}
			if prev, ok := lastMod[path]; !ok || info.ModTime().After(prev) {
				lastMod[path] = info.ModTime()
				_ = fi.IndexFile(path)
			}
			return nil
		})
	}
}

func (fi *FileIndexer) fullIndex() {
	var files []string
	_ = filepath.Walk(fi.workspaceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !fi.isIgnored(path) {
			files = append(files, path)
		}
		return nil
	})

	for i, path := range files {
		_ = fi.IndexFile(path)
		if fi.onProgress != nil {
			fi.onProgress(i+1, len(files))
		}
	}
}

// IsReady returns true when the initial index is complete.
func (fi *FileIndexer) IsReady() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.ready
}

// Search performs semantic search over the index.
func (fi *FileIndexer) Search(query string, k int) ([]IndexEntry, error) {
	embedding, err := fi.embedder.Embed(query)
	if err != nil {
		return nil, err
	}
	return fi.index.Search(embedding, k), nil
}

// LoadIgnorePatterns reads .gitignore and .vibecoderignore from the workspace root.
func (fi *FileIndexer) LoadIgnorePatterns() {
	var patterns []string
	for _, name := range []string{".gitignore", ".vibecoderignore"} {
		path := filepath.Join(fi.workspaceRoot, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				patterns = append(patterns, line)
			}
		}
		f.Close()
	}
	fi.mu.Lock()
	fi.ignorePatterns = patterns
	fi.mu.Unlock()
}

func (fi *FileIndexer) isIgnored(path string) bool {
	rel, err := filepath.Rel(fi.workspaceRoot, path)
	if err != nil {
		return false
	}
	fi.mu.RLock()
	patterns := fi.ignorePatterns
	fi.mu.RUnlock()

	for _, pattern := range patterns {
		matched, _ := filepath.Match(pattern, rel)
		if matched {
			return true
		}
		matched, _ = filepath.Match(pattern, filepath.Base(rel))
		if matched {
			return true
		}
	}
	return false
}
