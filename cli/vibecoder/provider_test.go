package vibecoder

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Mock provider helpers
// ─────────────────────────────────────────────────────────────────────────────

// mockProvider is a configurable Provider for testing.
type mockProvider struct {
	name string
	err  error // if non-nil, StreamChat returns this error
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	if m.err != nil {
		return nil, m.err
	}
	ch := make(chan StreamEvent, 1)
	ch <- StreamEvent{Token: "hello from " + m.name}
	close(ch)
	return ch, nil
}

func (m *mockProvider) Models() []ModelInfo { return nil }

func (m *mockProvider) HealthCheck(_ context.Context) error { return nil }

// ─────────────────────────────────────────────────────────────────────────────
// Property 1: Provider Chain Failover
//
// Validates: For any sequence of provider failures, the ProviderChain must:
//  1. Advance to the next provider in the chain
//  2. NOT retry the failed provider for that request
//
// ─────────────────────────────────────────────────────────────────────────────

// TestProviderChainFailover is a table-driven property test covering all
// meaningful combinations of failing/succeeding providers in a chain.
//
// **Validates: Requirements 1.2** (provider failover ordering)
func TestProviderChainFailover(t *testing.T) {
	quotaErr := fmt.Errorf("quota exceeded (429)")
	authErr := fmt.Errorf("auth error (401)")
	serverErr := fmt.Errorf("server error (500)")

	tests := []struct {
		name          string
		providers     []Provider
		preferred     string
		wantSuccess   bool
		wantProvider  string // name of provider that should serve the request
	}{
		{
			name: "first provider succeeds",
			providers: []Provider{
				&mockProvider{name: "a"},
				&mockProvider{name: "b"},
				&mockProvider{name: "c"},
			},
			preferred:    "a",
			wantSuccess:  true,
			wantProvider: "a",
		},
		{
			name: "first fails with quota, second succeeds",
			providers: []Provider{
				&mockProvider{name: "a", err: quotaErr},
				&mockProvider{name: "b"},
				&mockProvider{name: "c"},
			},
			preferred:    "a",
			wantSuccess:  true,
			wantProvider: "b",
		},
		{
			name: "first fails with auth, second succeeds",
			providers: []Provider{
				&mockProvider{name: "a", err: authErr},
				&mockProvider{name: "b"},
			},
			preferred:    "a",
			wantSuccess:  true,
			wantProvider: "b",
		},
		{
			name: "first two fail, third succeeds",
			providers: []Provider{
				&mockProvider{name: "a", err: quotaErr},
				&mockProvider{name: "b", err: serverErr},
				&mockProvider{name: "c"},
			},
			preferred:    "a",
			wantSuccess:  true,
			wantProvider: "c",
		},
		{
			name: "all providers fail",
			providers: []Provider{
				&mockProvider{name: "a", err: quotaErr},
				&mockProvider{name: "b", err: authErr},
				&mockProvider{name: "c", err: serverErr},
			},
			preferred:   "a",
			wantSuccess: false,
		},
		{
			name: "single provider fails",
			providers: []Provider{
				&mockProvider{name: "only", err: quotaErr},
			},
			preferred:   "only",
			wantSuccess: false,
		},
		{
			// After reordering: [b, a, c]. b fails → a is tried next.
			name: "preferred is middle, it fails, next in reordered chain succeeds",
			providers: []Provider{
				&mockProvider{name: "a"},
				&mockProvider{name: "b", err: quotaErr},
				&mockProvider{name: "c"},
			},
			preferred:    "b",
			wantSuccess:  true,
			wantProvider: "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewProviderChain(tt.providers, tt.preferred)
			req := ChatRequest{Model: "test-model", Stream: true}

			ch, err := chain.StreamChat(context.Background(), req)

			if tt.wantSuccess {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				// Drain the channel and collect the token to identify which provider responded
				var token string
				for ev := range ch {
					if ev.Token != "" {
						token = ev.Token
					}
				}
				expected := "hello from " + tt.wantProvider
				if token != expected {
					t.Errorf("expected token %q, got %q", expected, token)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			}
		})
	}
}

// TestProviderChainNoRetryOnFailure verifies that a failed provider is NOT
// retried for the same request — the chain advances strictly forward.
//
// **Validates: Requirements 1.2** (no retry of failed provider)
func TestProviderChainNoRetryOnFailure(t *testing.T) {
	callCount := 0
	failOnce := &countingMockProvider{
		name: "flaky",
		fn: func() error {
			callCount++
			return errors.New("always fails")
		},
	}
	good := &mockProvider{name: "good"}

	chain := NewProviderChain([]Provider{failOnce, good}, "flaky")
	req := ChatRequest{Model: "test-model", Stream: true}

	ch, err := chain.StreamChat(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for range ch {
	}

	if callCount != 1 {
		t.Errorf("expected flaky provider to be called exactly once, got %d", callCount)
	}
}

// countingMockProvider calls fn on each StreamChat invocation.
type countingMockProvider struct {
	name string
	fn   func() error
}

func (c *countingMockProvider) Name() string { return c.name }
func (c *countingMockProvider) StreamChat(_ context.Context, _ ChatRequest) (<-chan StreamEvent, error) {
	if err := c.fn(); err != nil {
		return nil, err
	}
	ch := make(chan StreamEvent, 1)
	ch <- StreamEvent{Token: "ok"}
	close(ch)
	return ch, nil
}
func (c *countingMockProvider) Models() []ModelInfo      { return nil }
func (c *countingMockProvider) HealthCheck(_ context.Context) error { return nil }

// ─────────────────────────────────────────────────────────────────────────────
// Property 2: Preferred Provider Ordering
//
// Validates: For any valid provider name configured as preferred, that provider
// must always appear at index 0 in the constructed ProviderChain.
//
// ─────────────────────────────────────────────────────────────────────────────

// TestPreferredProviderOrdering verifies that the named preferred provider is
// always placed at index 0 in the ProviderChain.
//
// **Validates: Requirements 1.2** (preferred provider ordering)
func TestPreferredProviderOrdering(t *testing.T) {
	providers := []Provider{
		&mockProvider{name: "openrouter"},
		&mockProvider{name: "groq"},
		&mockProvider{name: "mistral"},
		&mockProvider{name: "deepseek"},
		&mockProvider{name: "nvidia"},
	}

	tests := []struct {
		preferredName string
	}{
		{"openrouter"},
		{"groq"},
		{"mistral"},
		{"deepseek"},
		{"nvidia"},
	}

	for _, tt := range tests {
		t.Run("preferred="+tt.preferredName, func(t *testing.T) {
			chain := NewProviderChain(providers, tt.preferredName)

			if len(chain.providers) == 0 {
				t.Fatal("chain has no providers")
			}

			if chain.providers[0].Name() != tt.preferredName {
				t.Errorf("expected providers[0] to be %q, got %q",
					tt.preferredName, chain.providers[0].Name())
			}

			// Verify preferred index is 0
			if chain.preferred != 0 {
				t.Errorf("expected chain.preferred == 0, got %d", chain.preferred)
			}

			// Verify all original providers are still present
			if len(chain.providers) != len(providers) {
				t.Errorf("expected %d providers, got %d", len(providers), len(chain.providers))
			}
		})
	}
}

// TestPreferredProviderOrderingUnknownName verifies that an unknown preferred
// name falls back to index 0 without panicking.
//
// **Validates: Requirements 1.2** (graceful fallback)
func TestPreferredProviderOrderingUnknownName(t *testing.T) {
	providers := []Provider{
		&mockProvider{name: "a"},
		&mockProvider{name: "b"},
	}

	chain := NewProviderChain(providers, "nonexistent")

	// Should not panic and should have a valid preferred index
	if chain.preferred != 0 {
		t.Errorf("expected preferred=0 for unknown name, got %d", chain.preferred)
	}
	if len(chain.providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(chain.providers))
	}
}

// TestPreferredProviderOrderingAllNames is a property-style exhaustive test:
// for every provider in the list, constructing a chain with that provider as
// preferred must always result in it being at index 0.
//
// **Validates: Requirements 1.2** (preferred provider ordering — exhaustive)
func TestPreferredProviderOrderingAllNames(t *testing.T) {
	names := []string{"p0", "p1", "p2", "p3", "p4"}
	providers := make([]Provider, len(names))
	for i, n := range names {
		providers[i] = &mockProvider{name: n}
	}

	for _, preferred := range names {
		chain := NewProviderChain(providers, preferred)
		if chain.providers[0].Name() != preferred {
			t.Errorf("preferred=%q: expected providers[0]=%q, got %q",
				preferred, preferred, chain.providers[0].Name())
		}
	}
}
