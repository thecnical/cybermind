package vibecoder

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// InterjectionMsg is a message the user can inject mid-task.
type InterjectionMsg struct {
	Content string
}

// AgentLoopConfig holds configuration for the agent loop.
type AgentLoopConfig struct {
	MaxIterations   int     // default 50
	WarnAt          float64 // warn at this fraction of MaxIterations (default 0.8)
	CircuitBreakerN int     // consecutive errors before circuit opens (default 3)
	StuckHashCount  int     // same tool+params hash count before halt (default 3)
}

// AgentLoop orchestrates the think → decide → execute → observe cycle.
type AgentLoop struct {
	session       *Session
	provider      Provider
	toolEngine    *ToolEngine
	checkpoint    *CheckpointManager
	config        AgentLoopConfig
	interjections chan InterjectionMsg
	onToken       func(token string)        // callback for streaming tokens to TUI
	onToolStatus  func(tool, action string) // callback for tool status updates
	onWarn        func(msg string)          // callback for warnings
}

// NewAgentLoop creates an AgentLoop.
func NewAgentLoop(
	session *Session,
	provider Provider,
	toolEngine *ToolEngine,
	checkpoint *CheckpointManager,
	config AgentLoopConfig,
) *AgentLoop {
	if config.MaxIterations <= 0 {
		config.MaxIterations = 50
	}
	if config.WarnAt <= 0 {
		config.WarnAt = 0.8
	}
	if config.CircuitBreakerN <= 0 {
		config.CircuitBreakerN = 3
	}
	if config.StuckHashCount <= 0 {
		config.StuckHashCount = 3
	}
	return &AgentLoop{
		session:       session,
		provider:      provider,
		toolEngine:    toolEngine,
		checkpoint:    checkpoint,
		config:        config,
		interjections: make(chan InterjectionMsg, 16),
	}
}

// Interject sends a user message to be processed on the next loop iteration.
func (a *AgentLoop) Interject(msg InterjectionMsg) {
	select {
	case a.interjections <- msg:
	default:
		// Drop if channel is full
	}
}

// SetOnToken sets the callback for streaming tokens to the TUI.
func (a *AgentLoop) SetOnToken(fn func(token string)) {
	a.onToken = fn
}

// SetOnToolStatus sets the callback for tool execution status updates.
func (a *AgentLoop) SetOnToolStatus(fn func(tool, action string)) {
	a.onToolStatus = fn
}

// SetOnWarn sets the callback for warning messages.
func (a *AgentLoop) SetOnWarn(fn func(msg string)) {
	a.onWarn = fn
}

// Run executes the agent loop until the AI produces a response with no tool calls,
// the iteration limit is reached, or ctx is cancelled.
func (a *AgentLoop) Run(ctx context.Context) error {
	// Top-level panic recovery
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			logCrash(fmt.Sprintf("panic: %v\n%s", r, stack))
			if a.onWarn != nil {
				a.onWarn("CyberMind Neural encountered an unexpected error and recovered. Please try again.")
			}
		}
	}()

	iteration := 0
	consecutiveErrors := 0
	lastToolHash := ""
	sameHashCount := 0
	turnCount := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check for interjections
		select {
		case inj := <-a.interjections:
			a.session.AddMessage(Message{
				Role:      RoleUser,
				Content:   inj.Content,
				Timestamp: time.Now(),
			})
		default:
		}

		iteration++
		turnCount++

		// Warn at 80% of max iterations
		warnThreshold := int(float64(a.config.MaxIterations) * a.config.WarnAt)
		if iteration == warnThreshold && a.onWarn != nil {
			a.onWarn(fmt.Sprintf("Approaching iteration limit (%d/%d). Consider simplifying the task.", iteration, a.config.MaxIterations))
		}

		// Hard stop at max iterations
		if iteration > a.config.MaxIterations {
			return fmt.Errorf("agent loop: iteration limit reached (%d)", a.config.MaxIterations)
		}

		// Auto-checkpoint
		if a.checkpoint != nil && a.checkpoint.ShouldCheckpoint(turnCount) {
			_ = a.checkpoint.Save(a.session)
		}

		// Stream response from provider
		ch, err := a.provider.StreamChat(ctx, ChatRequest{
			Messages:  a.session.History,
			Model:     "", // caller sets model via provider
			MaxTokens: 4096,
			Stream:    true,
		})
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= a.config.CircuitBreakerN {
				return fmt.Errorf("circuit breaker: %d consecutive errors, last: %w", consecutiveErrors, err)
			}
			// Quota/rate-limit: save task checkpoint
			if a.checkpoint != nil {
				_ = a.checkpoint.SaveTask(TaskCheckpoint{
					SessionID: a.session.ID,
					TaskName:  "quota-pause",
					Timestamp: time.Now(),
				})
			}
			continue
		}
		consecutiveErrors = 0

		// Collect streamed response
		var responseContent string
		var toolCalls []ToolCall
		for event := range ch {
			if event.Error != nil {
				consecutiveErrors++
				break
			}
			if event.Token != "" {
				responseContent += event.Token
				if a.onToken != nil {
					a.onToken(event.Token)
				}
			}
			if event.ToolCall != nil {
				toolCalls = append(toolCalls, *event.ToolCall)
			}
		}

		// Add assistant message to history
		warned := a.session.AddMessage(Message{
			Role:      RoleAssistant,
			Content:   responseContent,
			ToolCalls: toolCalls,
			Timestamp: time.Now(),
			Tokens:    estimateTokens(responseContent),
		})
		if warned && a.onWarn != nil {
			a.onWarn("Context window is 90% full. Consider using /compress or /clear.")
		}

		// If no tool calls, the AI is done
		if len(toolCalls) == 0 {
			return nil
		}

		// Stuck loop detection: same tool+params hash > StuckHashCount consecutive times
		if len(toolCalls) > 0 {
			hash := toolCallHash(toolCalls[0])
			if hash == lastToolHash {
				sameHashCount++
				if sameHashCount >= a.config.StuckHashCount {
					return fmt.Errorf("agent loop: stuck — same tool call repeated %d times: %s(%s)",
						sameHashCount, toolCalls[0].Name, string(toolCalls[0].Params))
				}
			} else {
				lastToolHash = hash
				sameHashCount = 1
			}
		}

		// Execute tool calls
		if a.onToolStatus != nil {
			for _, tc := range toolCalls {
				a.onToolStatus(tc.Name, "executing")
			}
		}
		results := a.toolEngine.ExecuteBatch(ctx, toolCalls)

		// Check for circuit breaker
		errorCount := 0
		for _, r := range results {
			if r.Error != "" {
				errorCount++
			}
		}
		if errorCount >= a.config.CircuitBreakerN {
			consecutiveErrors += errorCount
			if consecutiveErrors >= a.config.CircuitBreakerN {
				return fmt.Errorf("circuit breaker: %d consecutive tool errors", consecutiveErrors)
			}
		} else {
			consecutiveErrors = 0
		}

		// Add tool results to history
		for _, r := range results {
			a.session.AddMessage(Message{
				Role:       RoleTool,
				ToolResult: &r,
				Timestamp:  time.Now(),
				Tokens:     estimateTokens(r.Output),
			})
		}
	}
}

// toolCallHash returns a simple hash string for a tool call (name + params).
func toolCallHash(tc ToolCall) string {
	return tc.Name + ":" + string(tc.Params)
}

// detectOutputLimit returns true if the response appears to be approaching the output token limit.
// Heuristic: response > 28000 tokens (≈112000 chars).
func detectOutputLimit(response string) bool {
	return len(response) > 112000
}

// logCrash writes a crash log to ~/.cybermind/neural_crash.log.
func logCrash(msg string) {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("crash: %s", msg)
		return
	}
	dir := filepath.Join(home, ".cybermind")
	_ = os.MkdirAll(dir, 0700)
	f, err := os.OpenFile(filepath.Join(dir, "neural_crash.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("crash: %s", msg)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), msg)
}
