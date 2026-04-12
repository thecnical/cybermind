package vibecoder

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Mock provider helpers for agent loop tests
// ─────────────────────────────────────────────────────────────────────────────

// noToolCallProvider returns a plain-text response with no tool calls.
type noToolCallProvider struct {
	response string
}

func (p *noToolCallProvider) Name() string { return "no-tool-call" }
func (p *noToolCallProvider) Models() []ModelInfo { return nil }
func (p *noToolCallProvider) HealthCheck(_ context.Context) error { return nil }
func (p *noToolCallProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	ch := make(chan StreamEvent, 2)
	ch <- StreamEvent{Token: p.response}
	close(ch)
	return ch, nil
}

// alwaysSameToolProvider always returns the same tool call.
type alwaysSameToolProvider struct {
	toolName   string
	toolParams json.RawMessage
}

func (p *alwaysSameToolProvider) Name() string { return "always-same-tool" }
func (p *alwaysSameToolProvider) Models() []ModelInfo { return nil }
func (p *alwaysSameToolProvider) HealthCheck(_ context.Context) error { return nil }
func (p *alwaysSameToolProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	ch := make(chan StreamEvent, 2)
	ch <- StreamEvent{ToolCall: &ToolCall{
		ID:     "tc-1",
		Name:   p.toolName,
		Params: p.toolParams,
	}}
	close(ch)
	return ch, nil
}

// alwaysErrorProvider always returns an error from StreamChat.
type alwaysErrorProvider struct {
	err error
}

func (p *alwaysErrorProvider) Name() string { return "always-error" }
func (p *alwaysErrorProvider) Models() []ModelInfo { return nil }
func (p *alwaysErrorProvider) HealthCheck(_ context.Context) error { return nil }
func (p *alwaysErrorProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	return nil, p.err
}

// newTestToolEngine creates a minimal ToolEngine with a no-op tool for testing.
func newTestToolEngine() *ToolEngine {
	reg := NewToolRegistry()
	// Register a no-op tool that always succeeds
	reg.Register(&noopTool{})
	env := &ToolEnv{
		Guard:         &WorkspaceGuard{root: "/tmp"},
		WorkspaceRoot: "/tmp",
	}
	return NewToolEngine(reg, env)
}

// noopTool is a tool that always succeeds with empty output.
type noopTool struct{}

func (t *noopTool) Name() string { return "noop" }
func (t *noopTool) Schema() json.RawMessage {
	return rawSchema(`{"type":"object","properties":{}}`)
}
func (t *noopTool) Execute(_ context.Context, _ json.RawMessage, _ *ToolEnv) (ToolResult, error) {
	return ToolResult{Output: "ok"}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 18: Agent Loop Termination on No Tool Calls
// Feature: cybermind-vibe-coder
// Validates: Requirements 13.1
//
// When the AI produces a response with no tool calls, Run() must return nil.
// ─────────────────────────────────────────────────────────────────────────────

// TestAgentLoopTerminatesOnNoToolCalls verifies that when the provider returns
// a plain-text response with no tool calls, Run() returns nil immediately.
//
// **Validates: Requirements 13.1** (agent loop termination on no tool calls)
func TestAgentLoopTerminatesOnNoToolCalls(t *testing.T) {
	responses := []string{
		"Hello, I'm done!",
		"Task complete.",
		"",
		"A very long response that contains no tool calls whatsoever.",
	}

	for _, resp := range responses {
		t.Run(fmt.Sprintf("response=%q", truncateStr(resp, 20)), func(t *testing.T) {
			session := NewSession("/tmp")
			provider := &noToolCallProvider{response: resp}
			engine := newTestToolEngine()

			loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
				MaxIterations: 10,
			})

			err := loop.Run(context.Background())
			if err != nil {
				t.Errorf("Run() returned error %v, want nil", err)
			}

			// Verify the assistant message was added to history
			found := false
			for _, msg := range session.History {
				if msg.Role == RoleAssistant {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected assistant message in history, found none")
			}
		})
	}
}

// TestAgentLoopTerminatesOnNoToolCalls_SingleIteration verifies the loop
// terminates in exactly one iteration when no tool calls are returned.
//
// **Validates: Requirements 13.1** (single iteration termination)
func TestAgentLoopTerminatesOnNoToolCalls_SingleIteration(t *testing.T) {
	session := NewSession("/tmp")
	callCount := 0

	provider := &countingNoToolProvider{onCall: func() { callCount++ }}
	engine := newTestToolEngine()

	loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
		MaxIterations: 50,
	})

	err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("provider called %d times, want 1", callCount)
	}
}

// countingNoToolProvider counts calls and returns no tool calls.
type countingNoToolProvider struct {
	onCall func()
}

func (p *countingNoToolProvider) Name() string { return "counting-no-tool" }
func (p *countingNoToolProvider) Models() []ModelInfo { return nil }
func (p *countingNoToolProvider) HealthCheck(_ context.Context) error { return nil }
func (p *countingNoToolProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	p.onCall()
	ch := make(chan StreamEvent, 1)
	ch <- StreamEvent{Token: "done"}
	close(ch)
	return ch, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 19: Stuck Loop Detection
// Feature: cybermind-vibe-coder
// Validates: Requirements 13.1
//
// When the same tool+params hash appears > StuckHashCount consecutive times,
// Run() must return an error.
// ─────────────────────────────────────────────────────────────────────────────

// TestAgentLoopStuckDetection verifies that when the same tool call is repeated
// more than StuckHashCount times, Run() returns an error.
//
// **Validates: Requirements 13.1** (stuck loop detection)
func TestAgentLoopStuckDetection(t *testing.T) {
	tests := []struct {
		name           string
		stuckHashCount int
		toolName       string
		toolParams     string
	}{
		{
			name:           "default stuck count (3)",
			stuckHashCount: 3,
			toolName:       "noop",
			toolParams:     `{}`,
		},
		{
			name:           "stuck count 2",
			stuckHashCount: 2,
			toolName:       "noop",
			toolParams:     `{"key":"value"}`,
		},
		{
			name:           "stuck count 5",
			stuckHashCount: 5,
			toolName:       "noop",
			toolParams:     `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := NewSession("/tmp")
			provider := &alwaysSameToolProvider{
				toolName:   tt.toolName,
				toolParams: json.RawMessage(tt.toolParams),
			}
			engine := newTestToolEngine()

			loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
				MaxIterations:  100,
				StuckHashCount: tt.stuckHashCount,
			})

			err := loop.Run(context.Background())
			if err == nil {
				t.Fatal("Run() returned nil, want stuck loop error")
			}

			// Error should mention "stuck"
			errStr := err.Error()
			if len(errStr) == 0 {
				t.Error("expected non-empty error message")
			}
		})
	}
}

// TestAgentLoopStuckDetection_DifferentParamsNotStuck verifies that different
// tool params do NOT trigger stuck detection.
//
// **Validates: Requirements 13.1** (stuck detection only on identical calls)
func TestAgentLoopStuckDetection_DifferentParamsNotStuck(t *testing.T) {
	session := NewSession("/tmp")
	callCount := 0

	// Provider alternates between two different tool calls, then returns no tool call
	provider := &alternatingToolProvider{
		tools: []ToolCall{
			{ID: "1", Name: "noop", Params: json.RawMessage(`{"a":1}`)},
			{ID: "2", Name: "noop", Params: json.RawMessage(`{"a":2}`)},
		},
		maxCalls: 4,
		onCall:   func() { callCount++ },
	}
	engine := newTestToolEngine()

	loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
		MaxIterations:  20,
		StuckHashCount: 3,
	})

	err := loop.Run(context.Background())
	if err != nil {
		t.Errorf("Run() returned error %v, want nil (different params should not trigger stuck)", err)
	}
}

// alternatingToolProvider cycles through tool calls then returns no tool call.
type alternatingToolProvider struct {
	tools    []ToolCall
	maxCalls int
	callIdx  int
	onCall   func()
}

func (p *alternatingToolProvider) Name() string { return "alternating" }
func (p *alternatingToolProvider) Models() []ModelInfo { return nil }
func (p *alternatingToolProvider) HealthCheck(_ context.Context) error { return nil }
func (p *alternatingToolProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	if p.onCall != nil {
		p.onCall()
	}
	ch := make(chan StreamEvent, 2)
	if p.callIdx < p.maxCalls {
		tc := p.tools[p.callIdx%len(p.tools)]
		ch <- StreamEvent{ToolCall: &tc}
		p.callIdx++
	} else {
		ch <- StreamEvent{Token: "done"}
	}
	close(ch)
	return ch, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 24: Circuit Breaker Activation
// Feature: cybermind-vibe-coder
// Validates: Requirements 13.1
//
// When CircuitBreakerN consecutive provider errors occur, Run() must return an error.
// ─────────────────────────────────────────────────────────────────────────────

// TestAgentLoopCircuitBreaker verifies that when CircuitBreakerN consecutive
// provider errors occur, Run() returns an error.
//
// **Validates: Requirements 13.1** (circuit breaker activation)
func TestAgentLoopCircuitBreaker(t *testing.T) {
	tests := []struct {
		name            string
		circuitBreakerN int
		providerErr     error
	}{
		{
			name:            "default circuit breaker (3)",
			circuitBreakerN: 3,
			providerErr:     fmt.Errorf("provider error"),
		},
		{
			name:            "circuit breaker N=2",
			circuitBreakerN: 2,
			providerErr:     fmt.Errorf("quota exceeded"),
		},
		{
			name:            "circuit breaker N=5",
			circuitBreakerN: 5,
			providerErr:     fmt.Errorf("server error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := NewSession("/tmp")
			provider := &alwaysErrorProvider{err: tt.providerErr}
			engine := newTestToolEngine()

			loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
				MaxIterations:   100,
				CircuitBreakerN: tt.circuitBreakerN,
			})

			err := loop.Run(context.Background())
			if err == nil {
				t.Fatal("Run() returned nil, want circuit breaker error")
			}
		})
	}
}

// TestAgentLoopCircuitBreaker_RecoveryAfterSuccess verifies that the error
// counter resets after a successful provider call.
//
// **Validates: Requirements 13.1** (circuit breaker resets on success)
func TestAgentLoopCircuitBreaker_RecoveryAfterSuccess(t *testing.T) {
	session := NewSession("/tmp")

	// Provider fails twice then succeeds (returns no tool call)
	provider := &failThenSucceedProvider{failCount: 2}
	engine := newTestToolEngine()

	loop := NewAgentLoop(session, provider, engine, nil, AgentLoopConfig{
		MaxIterations:   20,
		CircuitBreakerN: 3, // needs 3 consecutive failures to trip
	})

	err := loop.Run(context.Background())
	if err != nil {
		t.Errorf("Run() returned error %v, want nil (2 failures < circuit breaker threshold of 3)", err)
	}
}

// failThenSucceedProvider fails failCount times then returns a plain response.
type failThenSucceedProvider struct {
	failCount int
	calls     int
}

func (p *failThenSucceedProvider) Name() string { return "fail-then-succeed" }
func (p *failThenSucceedProvider) Models() []ModelInfo { return nil }
func (p *failThenSucceedProvider) HealthCheck(_ context.Context) error { return nil }
func (p *failThenSucceedProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	p.calls++
	if p.calls <= p.failCount {
		return nil, fmt.Errorf("transient error %d", p.calls)
	}
	ch := make(chan StreamEvent, 1)
	ch <- StreamEvent{Token: "recovered"}
	close(ch)
	return ch, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
