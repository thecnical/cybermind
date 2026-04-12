package vibecoder

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// generateUUID returns a random UUID v4 using crypto/rand (no external deps).
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewSession creates a new Session with sensible defaults.
func NewSession(workspaceRoot string) *Session {
	return &Session{
		ID:            generateUUID(),
		WorkspaceRoot: workspaceRoot,
		History:       []Message{},
		OpenFiles:     map[string]FileEntry{},
		EditMode:      EditModeGuard,
		InteractMode:  InteractModeAgent,
		EffortLevel:   EffortMedium,
		DebugMode:     false,
		UndoStack:     []FileSnapshot{},
		TokensUsed:    0,
		MaxTokens:     128000,
	}
}

// AddMessage appends a message to the session history and updates TokensUsed.
// Returns true if context usage has crossed the 90% warning threshold.
func (s *Session) AddMessage(msg Message) bool {
	s.History = append(s.History, msg)
	s.TokensUsed += msg.Tokens
	return s.TokensUsed > 0 && s.MaxTokens > 0 &&
		float64(s.TokensUsed)/float64(s.MaxTokens) >= 0.90
}

// ContextUsagePercent returns the percentage of context window used (0-100).
func (s *Session) ContextUsagePercent() float64 {
	if s.MaxTokens == 0 {
		return 0
	}
	pct := float64(s.TokensUsed) / float64(s.MaxTokens) * 100
	if pct > 100 {
		return 100
	}
	return pct
}

// PushUndo saves a file snapshot to the undo stack.
func (s *Session) PushUndo(snap FileSnapshot) {
	s.UndoStack = append(s.UndoStack, snap)
}

// PopUndo removes and returns the most recent file snapshot.
// Returns the snapshot and true if the stack was non-empty, or zero value and false.
func (s *Session) PopUndo() (FileSnapshot, bool) {
	if len(s.UndoStack) == 0 {
		return FileSnapshot{}, false
	}
	top := s.UndoStack[len(s.UndoStack)-1]
	s.UndoStack = s.UndoStack[:len(s.UndoStack)-1]
	return top, true
}

// SaveHistory serializes the session to ~/.cybermind/vibe_history/<timestamp>_<id>.json.
// API keys are masked and file contents are omitted (only paths stored).
func (s *Session) SaveHistory() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".cybermind", "vibe_history")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	sanitized := s.sanitizedCopy()

	data, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return err
	}

	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.json", ts, s.ID)
	path := filepath.Join(dir, filename)

	return atomicWrite(path, data)
}

// sanitizedCopy returns a copy of the session safe for disk storage:
// - OpenFiles has content cleared (only path, hash, and added_at kept)
// - UndoStack content cleared
func (s *Session) sanitizedCopy() Session {
	cp := *s
	cp.OpenFiles = make(map[string]FileEntry, len(s.OpenFiles))
	for k, v := range s.OpenFiles {
		cp.OpenFiles[k] = FileEntry{
			Path:    v.Path,
			Hash:    v.Hash,
			AddedAt: v.AddedAt,
		}
	}
	sanitizedUndo := make([]FileSnapshot, len(s.UndoStack))
	for i, snap := range s.UndoStack {
		sanitizedUndo[i] = FileSnapshot{Path: snap.Path}
	}
	cp.UndoStack = sanitizedUndo
	return cp
}

// Task 27: Session resume and history management

// ListRecentSessions returns the 10 most recent session history files.
func ListRecentSessions() ([]CheckpointMeta, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".cybermind", "vibe_history")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var metas []CheckpointMeta
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var s Session
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		metas = append(metas, CheckpointMeta{
			SessionID:     s.ID,
			WorkspaceRoot: s.WorkspaceRoot,
			Timestamp:     info.ModTime(),
			FilePath:      filepath.Join(dir, e.Name()),
		})
	}

	// Sort by timestamp descending
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Timestamp.After(metas[j].Timestamp)
	})

	if len(metas) > 10 {
		metas = metas[:10]
	}
	return metas, nil
}

// ResumeSession loads a session from a history file.
// Re-reads open files from disk (not from snapshot).
func ResumeSession(filePath string) (*Session, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	// Re-read open files from disk
	for path, entry := range s.OpenFiles {
		diskData, err := os.ReadFile(filepath.Join(s.WorkspaceRoot, path))
		if err == nil {
			entry.Content = string(diskData)
			entry.Hash = sha256sumBytes(diskData)
			s.OpenFiles[path] = entry
		}
	}
	return &s, nil
}
