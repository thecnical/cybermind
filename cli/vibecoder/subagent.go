package vibecoder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ─── Subagent System ──────────────────────────────────────────────────────────
//
// Subagents are isolated agent instances that run tasks in parallel.
// Each subagent has its own session, tool engine, and context window.
// Results are collected and returned to the parent agent.
//
// Use cases:
//   - Parallel file analysis (analyze 10 files simultaneously)
//   - Isolated experiments (try approach A and B in parallel)
//   - Specialized agents (one for research, one for writing)

// SubagentType defines the specialization of a subagent.
type SubagentType string

const (
	SubagentGeneral  SubagentType = "general"  // default — complex multi-step tasks
	SubagentExplore  SubagentType = "explore"  // fast codebase exploration
	SubagentPlan     SubagentType = "plan"     // architecture planning
	SubagentWrite    SubagentType = "write"    // code generation
	SubagentReview   SubagentType = "review"   // code review
	SubagentSecurity SubagentType = "security" // security analysis
)

// SubagentTask defines a task for a subagent to execute.
type SubagentTask struct {
	ID          string       // unique task identifier
	Type        SubagentType // specialization
	Task        string       // natural language task description
	Context     string       // additional context (file contents, etc.)
	Files       []string     // files to include in context
	MaxTokens   int          // max response tokens (default 4096)
	Timeout     time.Duration // task timeout (default 2 minutes)
}

// SubagentResult holds the output of a completed subagent task.
type SubagentResult struct {
	TaskID   string
	Type     SubagentType
	Output   string
	Error    error
	Elapsed  time.Duration
	Tokens   int
}

// SubagentOrchestrator manages parallel subagent execution.
type SubagentOrchestrator struct {
	provider      Provider
	toolEngine    *ToolEngine
	workspaceRoot string
	maxParallel   int // max concurrent subagents (default 4)
}

// NewSubagentOrchestrator creates an orchestrator.
func NewSubagentOrchestrator(provider Provider, toolEngine *ToolEngine, workspaceRoot string) *SubagentOrchestrator {
	return &SubagentOrchestrator{
		provider:      provider,
		toolEngine:    toolEngine,
		workspaceRoot: workspaceRoot,
		maxParallel:   4,
	}
}

// SetToolEngine wires the tool engine after construction (avoids circular dependency).
func (o *SubagentOrchestrator) SetToolEngine(engine *ToolEngine) {
	o.toolEngine = engine
}

// RunParallel executes multiple subagent tasks in parallel.
// Returns results in the same order as tasks.
func (o *SubagentOrchestrator) RunParallel(ctx context.Context, tasks []SubagentTask) []SubagentResult {
	if len(tasks) == 0 {
		return nil
	}

	results := make([]SubagentResult, len(tasks))
	sem := make(chan struct{}, o.maxParallel)
	var wg sync.WaitGroup

	for i, task := range tasks {
		wg.Add(1)
		go func(idx int, t SubagentTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = o.runSingle(ctx, t)
		}(i, task)
	}

	wg.Wait()
	return results
}

// RunSingle executes a single subagent task.
func (o *SubagentOrchestrator) RunSingle(ctx context.Context, task SubagentTask) SubagentResult {
	return o.runSingle(ctx, task)
}

// runSingle is the internal implementation.
func (o *SubagentOrchestrator) runSingle(ctx context.Context, task SubagentTask) SubagentResult {
	start := time.Now()
	result := SubagentResult{
		TaskID: task.ID,
		Type:   task.Type,
	}

	// Set timeout
	timeout := task.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build the subagent prompt
	prompt := o.buildSubagentPrompt(task)

	// Create isolated session for this subagent
	session := NewSession(o.workspaceRoot)
	session.AddMessage(Message{
		Role:      RoleUser,
		Content:   prompt,
		Timestamp: time.Now(),
		Tokens:    estimateTokens(prompt),
	})

	// Create agent loop for this subagent
	loop := NewAgentLoop(
		session,
		o.provider,
		o.toolEngine,
		nil, // no checkpoint for subagents
		AgentLoopConfig{
			MaxIterations:   20, // subagents have lower iteration limit
			CircuitBreakerN: 3,
			StuckHashCount:  3,
		},
	)

	// Collect output tokens
	var outputBuf string
	loop.SetOnToken(func(token string) {
		outputBuf += token
	})

	// Run the agent loop
	if err := loop.Run(taskCtx); err != nil {
		// Timeout or error — return partial output if any
		if outputBuf != "" {
			result.Output = outputBuf + fmt.Sprintf("\n[subagent stopped: %v]", err)
		} else {
			result.Error = err
		}
	} else {
		// Get final response from session history
		for i := len(session.History) - 1; i >= 0; i-- {
			msg := session.History[i]
			if msg.Role == RoleAssistant && msg.Content != "" {
				result.Output = msg.Content
				result.Tokens = msg.Tokens
				break
			}
		}
		if result.Output == "" {
			result.Output = outputBuf
		}
	}

	result.Elapsed = time.Since(start)
	return result
}

// buildSubagentPrompt constructs the prompt for a subagent based on its type.
func (o *SubagentOrchestrator) buildSubagentPrompt(task SubagentTask) string {
	var systemPrefix string
	switch task.Type {
	case SubagentExplore:
		systemPrefix = "You are a fast codebase explorer. Your job is to quickly find and summarize relevant code. Be concise and precise. Focus on file paths, function names, and key patterns."
	case SubagentPlan:
		systemPrefix = "You are a software architect. Your job is to create clear, actionable implementation plans. Think step by step. Consider edge cases, dependencies, and potential issues."
	case SubagentWrite:
		systemPrefix = "You are an expert code writer. Your job is to write clean, correct, well-documented code. Follow the project's existing patterns and conventions."
	case SubagentReview:
		systemPrefix = "You are a thorough code reviewer. Your job is to find bugs, security issues, and improvement opportunities. Be specific with file:line references."
	case SubagentSecurity:
		systemPrefix = "You are a security expert. Your job is to find vulnerabilities, misconfigurations, and security risks. Reference OWASP, CVEs, and CWEs where applicable."
	default:
		systemPrefix = "You are a helpful AI assistant. Complete the assigned task thoroughly and accurately."
	}

	prompt := systemPrefix + "\n\n"

	if task.Context != "" {
		prompt += "## Context\n" + task.Context + "\n\n"
	}

	if len(task.Files) > 0 {
		prompt += "## Files to analyze\n"
		for _, f := range task.Files {
			prompt += "- " + f + "\n"
		}
		prompt += "\n"
	}

	prompt += "## Task\n" + task.Task

	return prompt
}

// ─── SpawnSubagentTool — real implementation ──────────────────────────────────

// SubagentToolReal replaces the stub SpawnSubagentTool with real execution.
// It is registered in the tool registry when an orchestrator is available.
type SubagentToolReal struct {
	orchestrator *SubagentOrchestrator
}

func (t *SubagentToolReal) Name() string { return "spawn_subagent" }
func (t *SubagentToolReal) Schema() json.RawMessage {
	return rawSchema(`{
		"type": "object",
		"properties": {
			"task": {"type": "string", "description": "The task for the subagent to complete"},
			"type": {"type": "string", "enum": ["general","explore","plan","write","review","security"], "description": "Subagent specialization"},
			"context": {"type": "string", "description": "Additional context for the subagent"},
			"files": {"type": "array", "items": {"type": "string"}, "description": "Files to include in context"},
			"timeout_secs": {"type": "integer", "description": "Timeout in seconds (default 120)"}
		},
		"required": ["task"]
	}`)
}

func (t *SubagentToolReal) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Task        string   `json:"task"`
		Type        string   `json:"type"`
		Context     string   `json:"context"`
		Files       []string `json:"files"`
		TimeoutSecs int      `json:"timeout_secs"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	agentType := SubagentGeneral
	if p.Type != "" {
		agentType = SubagentType(p.Type)
	}

	timeout := time.Duration(p.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	task := SubagentTask{
		ID:      fmt.Sprintf("subagent-%d", time.Now().UnixNano()),
		Type:    agentType,
		Task:    p.Task,
		Context: p.Context,
		Files:   p.Files,
		Timeout: timeout,
	}

	result := t.orchestrator.RunSingle(ctx, task)
	if result.Error != nil {
		return ToolResult{Error: result.Error.Error()}, nil
	}

	output := fmt.Sprintf("[Subagent %s completed in %s]\n\n%s",
		result.Type, result.Elapsed.Round(time.Millisecond), result.Output)
	return ToolResult{Output: output}, nil
}

// ─── Parallel subagent tool ───────────────────────────────────────────────────

// SpawnParallelSubagentsTool runs multiple subagents in parallel.
type SpawnParallelSubagentsTool struct {
	orchestrator *SubagentOrchestrator
}

func (t *SpawnParallelSubagentsTool) Name() string { return "spawn_parallel_subagents" }
func (t *SpawnParallelSubagentsTool) Schema() json.RawMessage {
	return rawSchema(`{
		"type": "object",
		"properties": {
			"tasks": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"id": {"type": "string"},
						"task": {"type": "string"},
						"type": {"type": "string"},
						"context": {"type": "string"}
					},
					"required": ["id", "task"]
				}
			}
		},
		"required": ["tasks"]
	}`)
}

func (t *SpawnParallelSubagentsTool) Execute(ctx context.Context, params json.RawMessage, env *ToolEnv) (ToolResult, error) {
	var p struct {
		Tasks []struct {
			ID      string `json:"id"`
			Task    string `json:"task"`
			Type    string `json:"type"`
			Context string `json:"context"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ToolResult{}, err
	}

	tasks := make([]SubagentTask, len(p.Tasks))
	for i, pt := range p.Tasks {
		agentType := SubagentGeneral
		if pt.Type != "" {
			agentType = SubagentType(pt.Type)
		}
		tasks[i] = SubagentTask{
			ID:      pt.ID,
			Type:    agentType,
			Task:    pt.Task,
			Context: pt.Context,
			Timeout: 2 * time.Minute,
		}
	}

	results := t.orchestrator.RunParallel(ctx, tasks)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Parallel subagents completed (%d tasks):\n\n", len(results)))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("### Task: %s (%s, %s)\n", r.TaskID, r.Type, r.Elapsed.Round(time.Millisecond)))
		if r.Error != nil {
			sb.WriteString("Error: " + r.Error.Error() + "\n")
		} else {
			sb.WriteString(r.Output + "\n")
		}
		sb.WriteString("\n")
	}

	return ToolResult{Output: sb.String()}, nil
}
