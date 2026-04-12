package vibecoder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type CheckpointMeta struct {
	SessionID     string    `json:"session_id"`
	WorkspaceRoot string    `json:"workspace_root"`
	Timestamp     time.Time `json:"timestamp"`
	FilePath      string    `json:"file_path"`
}

type TaskCheckpoint struct {
	SessionID string    `json:"session_id"`
	TaskName  string    `json:"task_name"`
	Timestamp time.Time `json:"timestamp"`
	State     []byte    `json:"state"`
}

type CheckpointManager struct {
	dir           string
	intervalTurns int
}

// NewCheckpointManager creates a CheckpointManager storing checkpoints in dir.
// intervalTurns is how many turns between auto-saves (default 5).
func NewCheckpointManager(dir string, intervalTurns int) *CheckpointManager {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, ".cybermind", "checkpoints")
		}
	}
	if intervalTurns <= 0 {
		intervalTurns = 5
	}
	return &CheckpointManager{dir: dir, intervalTurns: intervalTurns}
}

// Save serializes the session to a checkpoint file atomically.
// File name: <timestamp>_<session-id>.checkpoint.json
// Uses atomicWrite (temp file + rename).
func (m *CheckpointManager) Save(s *Session) error {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return fmt.Errorf("checkpoint: mkdir %s: %w", m.dir, err)
	}

	sanitized := s.sanitizedCopy()
	data, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint: marshal: %w", err)
	}

	ts := time.Now().UTC().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.checkpoint.json", ts, s.ID)
	path := filepath.Join(m.dir, filename)

	return atomicWrite(path, data)
}

// LoadLatest finds and deserializes the most recent checkpoint for any session.
// Returns nil, nil if no checkpoints exist.
func (m *CheckpointManager) LoadLatest() (*Session, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("checkpoint: readdir: %w", err)
	}

	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var files []fileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if matched, _ := filepath.Match("*.checkpoint.json", e.Name()); !matched {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			path:    filepath.Join(m.dir, e.Name()),
			modTime: info.ModTime(),
		})
	}

	if len(files) == 0 {
		return nil, nil
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	data, err := os.ReadFile(files[0].path)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: read %s: %w", files[0].path, err)
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("checkpoint: unmarshal %s: %w", files[0].path, err)
	}
	return &s, nil
}

// List returns metadata for all checkpoints, sorted by timestamp descending.
func (m *CheckpointManager) List() ([]CheckpointMeta, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("checkpoint: readdir: %w", err)
	}

	var metas []CheckpointMeta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if matched, _ := filepath.Match("*.checkpoint.json", e.Name()); !matched {
			continue
		}
		path := filepath.Join(m.dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s Session
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		metas = append(metas, CheckpointMeta{
			SessionID:     s.ID,
			WorkspaceRoot: s.WorkspaceRoot,
			Timestamp:     info.ModTime(),
			FilePath:      path,
		})
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Timestamp.After(metas[j].Timestamp)
	})

	return metas, nil
}

// SaveTask saves a quota-aware task checkpoint.
func (m *CheckpointManager) SaveTask(checkpoint TaskCheckpoint) error {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return fmt.Errorf("checkpoint: mkdir %s: %w", m.dir, err)
	}

	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint: marshal task: %w", err)
	}

	ts := checkpoint.Timestamp.UTC().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_task.checkpoint.json", ts, checkpoint.SessionID)
	path := filepath.Join(m.dir, filename)

	return atomicWrite(path, data)
}

// ShouldCheckpoint returns true if the session has accumulated enough turns
// since the last checkpoint to warrant saving.
func (m *CheckpointManager) ShouldCheckpoint(turnCount int) bool {
	return m.intervalTurns > 0 && turnCount%m.intervalTurns == 0
}
