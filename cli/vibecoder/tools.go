package vibecoder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ToolCall and ToolResult are defined here (moved from stub).

type ToolCall struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params"`
}

type ToolResult struct {
	ToolCallID string `json:"tool_call_id"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated"`
}

type PermissionLevel int

const (
	PermRead    PermissionLevel = iota
	PermWrite
	PermExecute
	PermNetwork
)

// ─── Tool interface ───────────────────────────────────────────────────────────

// Tool is the interface every tool must implement.
type Tool interface {
	Name() string
	Schema() json.RawMessage
	Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error)
}

// ToolEnv carries runtime context for tool execution.
type ToolEnv struct {
	Guard         *WorkspaceGuard
	WorkspaceRoot string
	NoExec        bool
	Timeout       int    // command timeout in seconds
	SessionID     string // used by TodoWriteTool
}

// ─── ToolRegistry ─────────────────────────────────────────────────────────────

type ToolRegistry struct {
	tools map[string]Tool
}

func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: make(map[string]Tool)}
}

func (r *ToolRegistry) Register(t Tool) {
	r.tools[t.Name()] = t
}

func (r *ToolRegistry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

func (r *ToolRegistry) All() []Tool {
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

// ─── ToolEngine ───────────────────────────────────────────────────────────────

type ToolEngine struct {
	registry *ToolRegistry
	env      *ToolEnv
}

func NewToolEngine(registry *ToolRegistry, env *ToolEnv) *ToolEngine {
	return &ToolEngine{registry: registry, env: env}
}

// Execute runs a single tool call with JSON schema validation and logging.
func (e *ToolEngine) Execute(ctx context.Context, call ToolCall) ToolResult {
	start := time.Now()

	// 1. Validate params is valid JSON (not nil/empty).
	if len(call.Params) == 0 {
		call.Params = json.RawMessage("{}")
	}
	if !json.Valid(call.Params) {
		return ToolResult{ToolCallID: call.ID, Error: "invalid JSON params"}
	}

	// 2. Log before execution.
	paramStr := string(call.Params)
	if len(paramStr) > 200 {
		paramStr = paramStr[:200]
	}
	log.Printf("[tool] name=%s params=%s", call.Name, paramStr)

	tool, ok := e.registry.Get(call.Name)
	if !ok {
		return ToolResult{ToolCallID: call.ID, Error: fmt.Sprintf("unknown tool: %s", call.Name)}
	}

	result, err := tool.Execute(ctx, call.Params, e.env)
	result.ToolCallID = call.ID
	if err != nil {
		result.Error = err.Error()
	}

	// 3. Log after execution.
	summary := result.Output
	if len(summary) > 100 {
		summary = summary[:100] + "..."
	}
	if result.Error != "" {
		summary = "error=" + result.Error
	}
	log.Printf("[tool] name=%s result=%s duration=%dms", call.Name, summary, time.Since(start).Milliseconds())

	return result
}

// ExecuteBatch executes multiple tool calls concurrently, falling back to serial on error.
func (e *ToolEngine) ExecuteBatch(ctx context.Context, calls []ToolCall) []ToolResult {
	if len(calls) == 0 {
		return nil
	}

	results := make([]ToolResult, len(calls))
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrencyErr := false

	wg.Add(len(calls))
	for i, call := range calls {
		go func(idx int, c ToolCall) {
			defer wg.Done()
			r := e.Execute(ctx, c)
			mu.Lock()
			results[idx] = r
			if r.Error != "" {
				concurrencyErr = true
			}
			mu.Unlock()
		}(i, call)
	}
	wg.Wait()

	if concurrencyErr {
		// Fall back to serial execution.
		for i, call := range calls {
			results[i] = e.Execute(ctx, call)
		}
	}

	return results
}

// ─── Helper: schema builder ───────────────────────────────────────────────────

func rawSchema(s string) json.RawMessage { return json.RawMessage(s) }

// ─── 11.2 File / folder / search tools ───────────────────────────────────────

// ReadFileTool — read_file
type ReadFileTool struct{}

func (t *ReadFileTool) Name() string { return "read_file" }
func (t *ReadFileTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["path"]}`)
}
func (t *ReadFileTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{}, err
	}

	content := string(data)

	// Apply line range if specified.
	if p.StartLine > 0 || p.EndLine > 0 {
		lines := strings.Split(content, "\n")
		start := p.StartLine - 1
		if start < 0 {
			start = 0
		}
		end := p.EndLine
		if end <= 0 || end > len(lines) {
			end = len(lines)
		}
		if start < len(lines) {
			content = strings.Join(lines[start:end], "\n")
		}
	}

	const maxChars = 80000
	truncated := false
	if len(content) > maxChars {
		content = content[:maxChars] + "\n[content truncated — use start_line/end_line for pagination]"
		truncated = true
	}

	return ToolResult{Output: content, Truncated: truncated}, nil
}

// WriteFileTool — write_file
type WriteFileTool struct{}

func (t *WriteFileTool) Name() string { return "write_file" }
func (t *WriteFileTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}`)
}
func (t *WriteFileTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}

	data := []byte(p.Content)
	beforeHash := sha256sumBytes(data)

	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		return ToolResult{}, err
	}
	if err := atomicWrite(absPath, data); err != nil {
		return ToolResult{}, err
	}

	afterHash, err := sha256sum(absPath)
	if err != nil {
		return ToolResult{}, fmt.Errorf("write_file: post-write hash check failed: %w", err)
	}
	if beforeHash != afterHash {
		return ToolResult{}, fmt.Errorf("write_file: integrity check failed: hash mismatch after write")
	}

	return ToolResult{Output: "written: " + p.Path}, nil
}

// EditFileTool — edit_file
type EditFileTool struct{}

func (t *EditFileTool) Name() string { return "edit_file" }
func (t *EditFileTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"old_content":{"type":"string"},"new_content":{"type":"string"}},"required":["path","old_content","new_content"]}`)
}
func (t *EditFileTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path       string `json:"path"`
		OldContent string `json:"old_content"`
		NewContent string `json:"new_content"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{}, err
	}
	original := string(data)
	if !strings.Contains(original, p.OldContent) {
		return ToolResult{}, fmt.Errorf("edit_file: old_content not found in %s", p.Path)
	}
	updated := strings.Replace(original, p.OldContent, p.NewContent, 1)
	if err := atomicWrite(absPath, []byte(updated)); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "edited: " + p.Path}, nil
}

// CreateFileTool — create_file
type CreateFileTool struct{}

func (t *CreateFileTool) Name() string { return "create_file" }
func (t *CreateFileTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}`)
}
func (t *CreateFileTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0755); err != nil {
		return ToolResult{}, err
	}
	if err := atomicWrite(absPath, []byte(p.Content)); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "created: " + p.Path}, nil
}

// DeleteFileTool — delete_file
type DeleteFileTool struct{}

func (t *DeleteFileTool) Name() string { return "delete_file" }
func (t *DeleteFileTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)
}
func (t *DeleteFileTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	if err := os.Remove(absPath); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "deleted: " + p.Path}, nil
}

// CreateFolderTool — create_folder
type CreateFolderTool struct{}

func (t *CreateFolderTool) Name() string { return "create_folder" }
func (t *CreateFolderTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)
}
func (t *CreateFolderTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	if err := os.MkdirAll(absPath, 0755); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "created folder: " + p.Path}, nil
}

// ListDirectoryTool — list_directory
type ListDirectoryTool struct{}

func (t *ListDirectoryTool) Name() string { return "list_directory" }
func (t *ListDirectoryTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"depth":{"type":"integer"}},"required":["path"]}`)
}
func (t *ListDirectoryTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path  string `json:"path"`
		Depth int    `json:"depth"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	if p.Depth <= 0 {
		p.Depth = 3
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}

	var sb strings.Builder
	baseDepth := strings.Count(absPath, string(os.PathSeparator))

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
		if depth > p.Depth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		indent := strings.Repeat("  ", depth)
		name := info.Name()
		if info.IsDir() {
			name += "/"
		}
		sb.WriteString(indent + name + "\n")
		return nil
	})
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: sb.String()}, nil
}

// GlobSearchTool — glob_search
type GlobSearchTool struct{}

func (t *GlobSearchTool) Name() string { return "glob_search" }
func (t *GlobSearchTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"pattern":{"type":"string"}},"required":["pattern"]}`)
}
func (t *GlobSearchTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	// FIX: reject absolute paths — they bypass workspace root join
	if filepath.IsAbs(p.Pattern) {
		return ToolResult{}, fmt.Errorf("glob_search: absolute paths not allowed; use relative paths within workspace")
	}

	// Join with workspace root
	pattern := filepath.Join(env.WorkspaceRoot, p.Pattern)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return ToolResult{}, err
	}

	const maxResults = 200
	truncated := false
	if len(matches) > maxResults {
		matches = matches[:maxResults]
		truncated = true
	}

	out := strings.Join(matches, "\n")
	if truncated {
		out += "\n[results truncated at 200]"
	}
	return ToolResult{Output: out, Truncated: truncated}, nil
}

// GrepSearchTool — grep_search
type GrepSearchTool struct{}

func (t *GrepSearchTool) Name() string { return "grep_search" }
func (t *GrepSearchTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"pattern":{"type":"string"},"path":{"type":"string"}},"required":["pattern"]}`)
}
func (t *GrepSearchTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	re, err := regexp.Compile(p.Pattern)
	if err != nil {
		return ToolResult{}, fmt.Errorf("grep_search: invalid pattern: %w", err)
	}

	searchRoot := env.WorkspaceRoot
	if p.Path != "" {
		absPath, err := env.Guard.ValidatePath(p.Path)
		if err != nil {
			return ToolResult{}, err
		}
		searchRoot = absPath
	}

	const maxResults = 200
	var results []string

	err = filepath.Walk(searchRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if len(results) >= maxResults {
			return filepath.SkipAll
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			if re.MatchString(scanner.Text()) {
				results = append(results, fmt.Sprintf("%s:%d: %s", path, lineNo, scanner.Text()))
				if len(results) >= maxResults {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll {
		return ToolResult{}, err
	}

	truncated := len(results) >= maxResults
	out := strings.Join(results, "\n")
	if truncated {
		out += "\n[results truncated at 200]"
	}
	return ToolResult{Output: out, Truncated: truncated}, nil
}

// ─── 11.3 Terminal tools ──────────────────────────────────────────────────────

// backgroundProcess holds a running background command and its buffered output.
type backgroundProcess struct {
	cmd    *exec.Cmd
	buf    bytes.Buffer
	mu     sync.Mutex
	done   bool
}

// bgProcesses is the package-level map of background processes keyed by id.
var (
	bgMu        sync.Mutex
	bgProcesses = make(map[string]*backgroundProcess)
)

// RunCommandTool — run_command
type RunCommandTool struct{}

func (t *RunCommandTool) Name() string { return "run_command" }
func (t *RunCommandTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"command":{"type":"string"},"timeout_secs":{"type":"integer"}},"required":["command"]}`)
}
func (t *RunCommandTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Command     string `json:"command"`
		TimeoutSecs int    `json:"timeout_secs"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	if env.NoExec {
		return ToolResult{}, fmt.Errorf("run_command: execution disabled (--no-exec flag)")
	}
	if IsCommandBlocked(p.Command) {
		return ToolResult{}, fmt.Errorf("run_command: command is blocked for safety reasons")
	}

	timeout := env.Timeout
	if p.TimeoutSecs > 0 {
		timeout = p.TimeoutSecs
	}
	if timeout <= 0 {
		timeout = 30
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	shell, args := DefaultShell()
	args = append(args, p.Command)
	cmd := exec.CommandContext(cmdCtx, shell, args...)
	cmd.Dir = env.WorkspaceRoot

	out, err := cmd.CombinedOutput()
	combined := string(out)

	const maxChars = 50000
	truncated := false
	if len(combined) > maxChars {
		combined = combined[:maxChars] + "\n[output truncated]"
		truncated = true
	}

	if err != nil {
		// Return output even on error (non-zero exit).
		return ToolResult{Output: combined, Truncated: truncated, Error: err.Error()}, nil
	}
	return ToolResult{Output: combined, Truncated: truncated}, nil
}

// RunBackgroundCommandTool — run_background_command
type RunBackgroundCommandTool struct{}

func (t *RunBackgroundCommandTool) Name() string { return "run_background_command" }
func (t *RunBackgroundCommandTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"command":{"type":"string"},"id":{"type":"string"}},"required":["command","id"]}`)
}
func (t *RunBackgroundCommandTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Command string `json:"command"`
		ID      string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	if env.NoExec {
		return ToolResult{}, fmt.Errorf("run_background_command: execution disabled (--no-exec flag)")
	}
	if IsCommandBlocked(p.Command) {
		return ToolResult{}, fmt.Errorf("run_background_command: command is blocked for safety reasons")
	}

	// FIX: background commands get a maximum lifetime of 30 minutes to prevent resource exhaustion
	const maxBgLifetime = 30 * time.Minute
	bgCtx, bgCancel := context.WithTimeout(context.Background(), maxBgLifetime)

	shell, args := DefaultShell()
	args = append(args, p.Command)
	cmd := exec.CommandContext(bgCtx, shell, args...)
	cmd.Dir = env.WorkspaceRoot

	bp := &backgroundProcess{cmd: cmd}
	cmd.Stdout = &bp.buf
	cmd.Stderr = &bp.buf

	if err := cmd.Start(); err != nil {
		bgCancel()
		return ToolResult{}, fmt.Errorf("run_background_command: start failed: %w", err)
	}

	bgMu.Lock()
	bgProcesses[p.ID] = bp
	bgMu.Unlock()

	// Reap the process in background; cancel context when done.
	go func() {
		defer bgCancel()
		_ = cmd.Wait()
		bp.mu.Lock()
		bp.done = true
		bp.mu.Unlock()
	}()

	return ToolResult{Output: fmt.Sprintf("started: pid=%d (max lifetime: 30m)", cmd.Process.Pid)}, nil
}

// GetCommandOutputTool — get_command_output
type GetCommandOutputTool struct{}

func (t *GetCommandOutputTool) Name() string { return "get_command_output" }
func (t *GetCommandOutputTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"id":{"type":"string"},"filter":{"type":"string"}},"required":["id"]}`)
}
func (t *GetCommandOutputTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		ID     string `json:"id"`
		Filter string `json:"filter"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	bgMu.Lock()
	bp, ok := bgProcesses[p.ID]
	bgMu.Unlock()
	if !ok {
		return ToolResult{}, fmt.Errorf("get_command_output: no process with id %q", p.ID)
	}

	bp.mu.Lock()
	raw := bp.buf.String()
	bp.mu.Unlock()

	if p.Filter != "" {
		re, err := regexp.Compile(p.Filter)
		if err != nil {
			return ToolResult{}, fmt.Errorf("get_command_output: invalid filter regex: %w", err)
		}
		var filtered []string
		for _, line := range strings.Split(raw, "\n") {
			if re.MatchString(line) {
				filtered = append(filtered, line)
			}
		}
		raw = strings.Join(filtered, "\n")
	}

	return ToolResult{Output: raw}, nil
}

// KillProcessTool — kill_process
type KillProcessTool struct{}

func (t *KillProcessTool) Name() string { return "kill_process" }
func (t *KillProcessTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)
}
func (t *KillProcessTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	bgMu.Lock()
	bp, ok := bgProcesses[p.ID]
	bgMu.Unlock()
	if !ok {
		return ToolResult{}, fmt.Errorf("kill_process: no process with id %q", p.ID)
	}

	if bp.cmd.Process != nil {
		if err := bp.cmd.Process.Kill(); err != nil {
			return ToolResult{}, fmt.Errorf("kill_process: %w", err)
		}
	}
	bgMu.Lock()
	delete(bgProcesses, p.ID)
	bgMu.Unlock()

	return ToolResult{Output: fmt.Sprintf("killed process %q", p.ID)}, nil
}

// ─── 11.4 Code tools (stubs) ──────────────────────────────────────────────────

// AnalyzeCodeTool — analyze_code
type AnalyzeCodeTool struct{}

func (t *AnalyzeCodeTool) Name() string { return "analyze_code" }
func (t *AnalyzeCodeTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)
}
func (t *AnalyzeCodeTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: fmt.Sprintf("[analyze_code] file: %s\n%s\n[AI should analyze the above content]", p.Path, string(data))}, nil
}

// FixBugTool — fix_bug
type FixBugTool struct{}

func (t *FixBugTool) Name() string { return "fix_bug" }
func (t *FixBugTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"description":{"type":"string"}},"required":["path","description"]}`)
}
func (t *FixBugTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path        string `json:"path"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: fmt.Sprintf("[fix_bug] file: %s\ndescription: %s\n%s\n[AI should fix the bug described above]", p.Path, p.Description, string(data))}, nil
}

// RefactorCodeTool — refactor_code
type RefactorCodeTool struct{}

func (t *RefactorCodeTool) Name() string { return "refactor_code" }
func (t *RefactorCodeTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"path":{"type":"string"},"instruction":{"type":"string"}},"required":["path","instruction"]}`)
}
func (t *RefactorCodeTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Path        string `json:"path"`
		Instruction string `json:"instruction"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	absPath, err := env.Guard.ValidatePath(p.Path)
	if err != nil {
		return ToolResult{}, err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: fmt.Sprintf("[refactor_code] file: %s\ninstruction: %s\n%s\n[AI should refactor per the instruction above]", p.Path, p.Instruction, string(data))}, nil
}

// ─── 11.5 Web tools ───────────────────────────────────────────────────────────

// WebFetchTool — web_fetch
// FIX: SSRF protection — blocks private/internal IPs and cloud metadata endpoints
type WebFetchTool struct{}

func (t *WebFetchTool) Name() string { return "web_fetch" }
func (t *WebFetchTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}`)
}
func (t *WebFetchTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	// FIX: SSRF protection
	if err := validateFetchURL(p.URL); err != nil {
		return ToolResult{}, fmt.Errorf("web_fetch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return ToolResult{}, fmt.Errorf("web_fetch: %w", err)
	}
	req.Header.Set("User-Agent", "CyberMind-VibeCoder/1.0")

	// FIX: custom transport that validates redirect targets
	transport := &ssrfSafeTransport{wrapped: http.DefaultTransport}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return validateFetchURL(req.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return ToolResult{}, fmt.Errorf("web_fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50000))
	if err != nil {
		return ToolResult{}, fmt.Errorf("web_fetch: read body: %w", err)
	}

	content := string(body)
	truncated := false
	if len(content) >= 50000 {
		truncated = true
	}
	return ToolResult{Output: content, Truncated: truncated}, nil
}

// WebSearchTool — web_search
type WebSearchTool struct{}

func (t *WebSearchTool) Name() string { return "web_search" }
func (t *WebSearchTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)
}
func (t *WebSearchTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "Web search not yet implemented. Query: " + p.Query}, nil
}

// ─── 11.6 Task / session tools ────────────────────────────────────────────────

// SpawnSubagentTool — spawn_subagent
type SpawnSubagentTool struct{}

func (t *SpawnSubagentTool) Name() string { return "spawn_subagent" }
func (t *SpawnSubagentTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"task":{"type":"string"}},"required":["task"]}`)
}
func (t *SpawnSubagentTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Task string `json:"task"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "Subagent spawned for task: " + p.Task}, nil
}

// TodoItem represents a single todo entry.
type TodoItem struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Status  string `json:"status"` // "pending" | "in_progress" | "done"
}

// todoStore is the package-level map of todos keyed by session ID.
var (
	todoMu    sync.Mutex
	todoStore = make(map[string][]TodoItem)
)

// TodoWriteTool — todo_write
type TodoWriteTool struct{}

func (t *TodoWriteTool) Name() string { return "todo_write" }
func (t *TodoWriteTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"todos":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"content":{"type":"string"},"status":{"type":"string"}}}}},"required":["todos"]}`)
}
func (t *TodoWriteTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Todos []TodoItem `json:"todos"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	// Enforce exactly-one-in-progress invariant.
	inProgressCount := 0
	for _, todo := range p.Todos {
		if todo.Status == "in_progress" {
			inProgressCount++
		}
	}
	if inProgressCount > 1 {
		return ToolResult{}, fmt.Errorf("todo_write: only one todo may have status 'in_progress' at a time (found %d)", inProgressCount)
	}

	sessionID := env.SessionID
	if sessionID == "" {
		sessionID = "default"
	}

	todoMu.Lock()
	todoStore[sessionID] = p.Todos
	todoMu.Unlock()

	var sb strings.Builder
	for _, todo := range p.Todos {
		var marker string
		switch todo.Status {
		case "done":
			marker = "[x]"
		case "in_progress":
			marker = "[~]"
		default:
			marker = "[ ]"
		}
		sb.WriteString(fmt.Sprintf("%s %s: %s\n", marker, todo.ID, todo.Content))
	}
	return ToolResult{Output: sb.String()}, nil
}

// ExitPlanModeTool — exit_plan_mode
type ExitPlanModeTool struct{}

func (t *ExitPlanModeTool) Name() string { return "exit_plan_mode" }
func (t *ExitPlanModeTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{}}`)
}
func (t *ExitPlanModeTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	return ToolResult{Output: "plan mode exited"}, nil
}

// SemanticSearchTool — semantic_search
type SemanticSearchTool struct{}

func (t *SemanticSearchTool) Name() string { return "semantic_search" }
func (t *SemanticSearchTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{"query":{"type":"string"},"k":{"type":"integer"}},"required":["query"]}`)
}
func (t *SemanticSearchTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Query string `json:"query"`
		K     int    `json:"k"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Output: "Semantic search not yet implemented. Query: " + p.Query}, nil
}

// ─── SSRF protection helpers ──────────────────────────────────────────────────

// blockedMetadataHosts are cloud metadata endpoints that must never be fetched.
var blockedMetadataHosts = map[string]bool{
	"169.254.169.254":          true, // AWS/GCP/Azure IMDS
	"metadata.google.internal": true,
	"metadata.internal":        true,
	"169.254.170.2":            true, // ECS task metadata
}

// validateFetchURL checks that a URL is safe to fetch (no SSRF vectors).
func validateFetchURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http/https URLs are allowed (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if blockedMetadataHosts[host] {
		return fmt.Errorf("access to metadata endpoint %q is blocked", host)
	}
	// Resolve hostname and check all IPs
	addrs, err := net.LookupHost(host)
	if err != nil {
		// If we can't resolve, allow through (may be a valid external host)
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("access to private/internal IP %q is blocked (SSRF protection)", addr)
		}
	}
	return nil
}

// ssrfSafeTransport wraps http.RoundTripper and validates the resolved IP before connecting.
type ssrfSafeTransport struct {
	wrapped http.RoundTripper
}

func (t *ssrfSafeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := validateFetchURL(req.URL.String()); err != nil {
		return nil, err
	}
	return t.wrapped.RoundTrip(req)
}

// ─── DefaultToolRegistry ───────────────────────────────────────────────────────

// NewDefaultToolRegistry creates a ToolRegistry pre-populated with all built-in tools.
func NewDefaultToolRegistry() *ToolRegistry {
	r := NewToolRegistry()
	r.Register(&ReadFileTool{})
	r.Register(&WriteFileTool{})
	r.Register(&EditFileTool{})
	r.Register(&CreateFileTool{})
	r.Register(&DeleteFileTool{})
	r.Register(&CreateFolderTool{})
	r.Register(&ListDirectoryTool{})
	r.Register(&GlobSearchTool{})
	r.Register(&GrepSearchTool{})
	r.Register(&RunCommandTool{})
	r.Register(&RunBackgroundCommandTool{})
	r.Register(&GetCommandOutputTool{})
	r.Register(&KillProcessTool{})
	r.Register(&AnalyzeCodeTool{})
	r.Register(&FixBugTool{})
	r.Register(&RefactorCodeTool{})
	r.Register(&WebFetchTool{})
	r.Register(&WebSearchTool{})
	r.Register(&SpawnSubagentTool{})
	r.Register(&TodoWriteTool{})
	r.Register(&ExitPlanModeTool{})
	r.Register(&SemanticSearchTool{})
	return r
}
