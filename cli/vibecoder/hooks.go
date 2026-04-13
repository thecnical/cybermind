package vibecoder

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── Hooks System ─────────────────────────────────────────────────────────────
//
// Hooks fire automatically on IDE/agent events. They can run shell commands
// or inject prompts into the agent loop.
//
// Hook files live in:
//   .kiro/hooks/*.json   — project-scoped hooks
//   ~/.cybermind/hooks/  — user-scoped hooks
//
// Hook event types:
//   fileEdited      — after a file is written by a tool
//   fileCreated     — after a new file is created
//   fileDeleted     — after a file is deleted
//   agentStop       — after the agent loop completes
//   preToolUse      — before a tool executes (can block)
//   postToolUse     — after a tool executes
//   taskComplete    — after a todo item is marked done
//   sessionStart    — when a new session begins
//   sessionEnd      — when a session ends

// HookEventType identifies what triggered the hook.
type HookEventType string

const (
	HookEventFileEdited   HookEventType = "fileEdited"
	HookEventFileCreated  HookEventType = "fileCreated"
	HookEventFileDeleted  HookEventType = "fileDeleted"
	HookEventAgentStop    HookEventType = "agentStop"
	HookEventPreToolUse   HookEventType = "preToolUse"
	HookEventPostToolUse  HookEventType = "postToolUse"
	HookEventTaskComplete HookEventType = "taskComplete"
	HookEventSessionStart HookEventType = "sessionStart"
	HookEventSessionEnd   HookEventType = "sessionEnd"
)

// HookActionType defines what the hook does when triggered.
type HookActionType string

const (
	HookActionRunCommand HookActionType = "runCommand"
	HookActionInjectPrompt HookActionType = "injectPrompt"
)

// HookWhen defines the trigger condition for a hook.
type HookWhen struct {
	Type     HookEventType `json:"type" yaml:"type"`
	Patterns []string      `json:"patterns,omitempty" yaml:"patterns,omitempty"` // file glob patterns
	Tools    []string      `json:"tools,omitempty" yaml:"tools,omitempty"`       // tool name filter
}

// HookThen defines what happens when the hook fires.
type HookThen struct {
	Type    HookActionType `json:"type" yaml:"type"`
	Command string         `json:"command,omitempty" yaml:"command,omitempty"`
	Prompt  string         `json:"prompt,omitempty" yaml:"prompt,omitempty"`
	Timeout int            `json:"timeout,omitempty" yaml:"timeout,omitempty"` // seconds
}

// Hook is a single hook definition.
type Hook struct {
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	When        HookWhen `json:"when" yaml:"when"`
	Then        HookThen `json:"then" yaml:"then"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	SourcePath  string   `json:"-" yaml:"-"`
	Scope       string   `json:"-" yaml:"-"` // "project" | "user"
}

// HookEvent carries context about what triggered the hook.
type HookEvent struct {
	Type      HookEventType
	FilePath  string // for file events
	ToolName  string // for tool events
	ToolInput string // for tool events (JSON)
	TaskID    string // for task events
	Extra     map[string]string
}

// HookResult is returned after a hook fires.
type HookResult struct {
	Hook    *Hook
	Output  string
	Error   error
	Blocked bool   // for preToolUse hooks that deny execution
	Elapsed time.Duration
}

// HookRegistry holds all loaded hooks.
type HookRegistry struct {
	mu    sync.RWMutex
	hooks []*Hook
}

// NewHookRegistry creates an empty registry.
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{}
}

// Load scans hook directories and loads all hook files.
func (r *HookRegistry) Load(workspaceRoot string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = nil

	// 1. User-scoped hooks
	home, err := os.UserHomeDir()
	if err == nil {
		userDir := filepath.Join(home, ".cybermind", "hooks")
		_ = r.loadDir(userDir, "user")
	}

	// 2. Project-scoped hooks (override user)
	projectDir := filepath.Join(workspaceRoot, ".kiro", "hooks")
	_ = r.loadDir(projectDir, "project")

	return nil
}

// loadDir loads all .json and .yaml hook files from a directory.
func (r *HookRegistry) loadDir(dir, scope string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		hook, err := loadHookFile(path, scope)
		if err != nil {
			continue
		}
		if hook.Enabled {
			r.hooks = append(r.hooks, hook)
		}
	}
	return nil
}

// Fire triggers all matching hooks for an event.
// Returns results from all hooks that fired.
func (r *HookRegistry) Fire(event HookEvent, workspaceRoot string) []HookResult {
	r.mu.RLock()
	matching := r.matchingHooks(event)
	r.mu.RUnlock()

	if len(matching) == 0 {
		return nil
	}

	results := make([]HookResult, 0, len(matching))
	for _, hook := range matching {
		result := r.executeHook(hook, event, workspaceRoot)
		results = append(results, result)
	}
	return results
}

// FirePreTool fires preToolUse hooks and returns whether execution is blocked.
func (r *HookRegistry) FirePreTool(toolName, toolInput, workspaceRoot string) (blocked bool, reason string) {
	event := HookEvent{
		Type:      HookEventPreToolUse,
		ToolName:  toolName,
		ToolInput: toolInput,
	}
	results := r.Fire(event, workspaceRoot)
	for _, res := range results {
		if res.Blocked {
			return true, res.Output
		}
		if res.Error != nil {
			// Hook error doesn't block by default
			continue
		}
		// Check if output contains denial keywords
		out := strings.ToLower(res.Output)
		if strings.Contains(out, "denied") || strings.Contains(out, "blocked") || strings.Contains(out, "not allowed") {
			return true, res.Output
		}
	}
	return false, ""
}

// matchingHooks returns hooks that match the given event.
func (r *HookRegistry) matchingHooks(event HookEvent) []*Hook {
	var matching []*Hook
	for _, hook := range r.hooks {
		if hook.When.Type != event.Type {
			continue
		}
		// File pattern filter
		if len(hook.When.Patterns) > 0 && event.FilePath != "" {
			matched := false
			for _, pattern := range hook.When.Patterns {
				if ok, _ := filepath.Match(pattern, filepath.Base(event.FilePath)); ok {
					matched = true
					break
				}
				// Also try full path match
				if ok, _ := filepath.Match(pattern, event.FilePath); ok {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		// Tool name filter
		if len(hook.When.Tools) > 0 && event.ToolName != "" {
			matched := false
			for _, t := range hook.When.Tools {
				if t == event.ToolName || t == "*" {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		matching = append(matching, hook)
	}
	return matching
}

// executeHook runs a single hook and returns the result.
func (r *HookRegistry) executeHook(hook *Hook, event HookEvent, workspaceRoot string) HookResult {
	start := time.Now()
	result := HookResult{Hook: hook}

	switch hook.Then.Type {
	case HookActionRunCommand:
		result.Output, result.Error = r.runCommand(hook, event, workspaceRoot)

	case HookActionInjectPrompt:
		// Prompt injection is handled by the caller (agent loop)
		result.Output = r.expandPrompt(hook.Then.Prompt, event)

	default:
		result.Error = fmt.Errorf("unknown hook action: %s", hook.Then.Type)
	}

	result.Elapsed = time.Since(start)
	return result
}

// runCommand executes the hook's shell command.
func (r *HookRegistry) runCommand(hook *Hook, event HookEvent, workspaceRoot string) (string, error) {
	cmd := r.expandVars(hook.Then.Command, event)

	timeout := hook.Then.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	shell, args := DefaultShell()
	args = append(args, cmd)
	execCmd := exec.Command(shell, args...)
	execCmd.Dir = workspaceRoot

	// Set event context as env vars
	execCmd.Env = append(os.Environ(),
		"CYBERMIND_EVENT="+string(event.Type),
		"CYBERMIND_FILE="+event.FilePath,
		"CYBERMIND_TOOL="+event.ToolName,
	)

	done := make(chan struct{})
	var out []byte
	var cmdErr error
	go func() {
		out, cmdErr = execCmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
		return string(out), cmdErr
	case <-time.After(time.Duration(timeout) * time.Second):
		if execCmd.Process != nil {
			execCmd.Process.Kill()
		}
		return "", fmt.Errorf("hook %q timed out after %ds", hook.Name, timeout)
	}
}

// expandVars replaces $FILE, $TOOL, $EVENT placeholders in a string.
func (r *HookRegistry) expandVars(s string, event HookEvent) string {
	s = strings.ReplaceAll(s, "$FILE", event.FilePath)
	s = strings.ReplaceAll(s, "$TOOL", event.ToolName)
	s = strings.ReplaceAll(s, "$EVENT", string(event.Type))
	s = strings.ReplaceAll(s, "${FILE}", event.FilePath)
	s = strings.ReplaceAll(s, "${TOOL}", event.ToolName)
	s = strings.ReplaceAll(s, "${EVENT}", string(event.Type))
	return s
}

// expandPrompt expands a prompt template with event context.
func (r *HookRegistry) expandPrompt(prompt string, event HookEvent) string {
	return r.expandVars(prompt, event)
}

// ─── Hook file loader ─────────────────────────────────────────────────────────

func loadHookFile(path, scope string) (*Hook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	hook := &Hook{
		SourcePath: path,
		Scope:      scope,
		Enabled:    true, // default enabled
	}

	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(data, hook); err != nil {
			return nil, fmt.Errorf("hook %s: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, hook); err != nil {
			return nil, fmt.Errorf("hook %s: %w", path, err)
		}
	}

	if hook.Name == "" {
		base := filepath.Base(path)
		hook.Name = strings.TrimSuffix(strings.TrimSuffix(base, ".json"), ".yaml")
	}

	return hook, nil
}

// ─── Built-in hooks ───────────────────────────────────────────────────────────

// BuiltinHooks are example hooks installed on first run.
var BuiltinHooks = map[string]string{
	"lint-on-save.json": `{
  "name": "Lint on Save",
  "version": "1.0.0",
  "description": "Run linter after file edits",
  "enabled": false,
  "when": {
    "type": "fileEdited",
    "patterns": ["*.ts", "*.tsx", "*.js", "*.jsx"]
  },
  "then": {
    "type": "runCommand",
    "command": "npm run lint --silent 2>&1 | head -20",
    "timeout": 30
  }
}`,
	"test-on-save.json": `{
  "name": "Test on Save",
  "version": "1.0.0",
  "description": "Run tests after Go file edits",
  "enabled": false,
  "when": {
    "type": "fileEdited",
    "patterns": ["*.go"]
  },
  "then": {
    "type": "runCommand",
    "command": "go test ./... -count=1 -timeout 30s 2>&1 | tail -20",
    "timeout": 60
  }
}`,
	"security-check.json": `{
  "name": "Security Check",
  "version": "1.0.0",
  "description": "Block writes to sensitive files",
  "enabled": false,
  "when": {
    "type": "preToolUse",
    "tools": ["write_file", "edit_file"]
  },
  "then": {
    "type": "runCommand",
    "command": "echo 'allowed'",
    "timeout": 5
  }
}`,
}

// InstallBuiltinHooks writes example hooks to ~/.cybermind/hooks/ if not present.
func InstallBuiltinHooks() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hooksDir := filepath.Join(home, ".cybermind", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return err
	}
	for name, content := range BuiltinHooks {
		path := filepath.Join(hooksDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("install hook %s: %w", name, err)
			}
		}
	}
	return nil
}
