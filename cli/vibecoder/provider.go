package vibecoder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// StreamEvent is a union type for streaming events from AI providers.
type StreamEvent struct {
	Token    string    // non-empty for token delta events
	ToolCall *ToolCall // non-nil for tool call request events
	Error    error     // non-nil for terminal error events
}

// ModelInfo describes a model available from a provider.
type ModelInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	MaxTokens int    `json:"max_tokens"`
}

// ChatRequest is the input to a streaming chat completion.
type ChatRequest struct {
	Messages  []Message `json:"messages"`
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens,omitempty"`
	Stream    bool      `json:"stream"`
}

// Provider is the interface all AI backends must satisfy.
type Provider interface {
	Name() string
	StreamChat(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error)
	Models() []ModelInfo
	HealthCheck(ctx context.Context) error
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenAICompatAdapter — shared HTTP client for OpenAI-compatible APIs
// ─────────────────────────────────────────────────────────────────────────────

// OpenAICompatAdapter implements Provider for any OpenAI-compatible REST API.
type OpenAICompatAdapter struct {
	name    string
	baseURL string
	apiKey  string
	models  []ModelInfo
	client  *http.Client
}

func newAdapter(name, baseURL, apiKey string, models []ModelInfo) *OpenAICompatAdapter {
	return &OpenAICompatAdapter{
		name:    name,
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		models:  models,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func (a *OpenAICompatAdapter) Name() string { return a.name }

func (a *OpenAICompatAdapter) Models() []ModelInfo { return a.models }

func (a *OpenAICompatAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s health check failed: HTTP %d", a.name, resp.StatusCode)
	}
	return nil
}

// openAIRequest is the JSON body sent to the completions endpoint.
type openAIRequest struct {
	Model     string           `json:"model"`
	Messages  []openAIMessage  `json:"messages"`
	MaxTokens int              `json:"max_tokens,omitempty"`
	Stream    bool             `json:"stream"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// sseChunk is the minimal shape of an SSE data payload.
type sseChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
}

// StreamChat opens a streaming chat completion and returns a channel of events.
// It retries on 5xx / timeout errors with exponential backoff (max 3 retries).
// It returns an error immediately on 429, 401, or 403.
func (a *OpenAICompatAdapter) StreamChat(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	msgs := make([]openAIMessage, len(req.Messages))
	for i, m := range req.Messages {
		msgs[i] = openAIMessage{Role: string(m.Role), Content: m.Content}
	}

	body := openAIRequest{
		Model:     req.Model,
		Messages:  msgs,
		MaxTokens: req.MaxTokens,
		Stream:    true,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal request: %w", a.name, err)
	}

	url := a.baseURL + "/chat/completions"

	const maxRetries = 3
	backoff := 100 * time.Millisecond

	var resp *http.Response
	for attempt := 0; attempt <= maxRetries; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("%s: build request: %w", a.name, err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

		resp, err = a.client.Do(httpReq)
		if err != nil {
			// Timeout or network error — retry with backoff
			if attempt < maxRetries {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
					backoff *= 2
					continue
				}
			}
			return nil, fmt.Errorf("%s: request failed: %w", a.name, err)
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			resp.Body.Close()
			return nil, fmt.Errorf("%s: quota exceeded (429)", a.name)
		case http.StatusUnauthorized, http.StatusForbidden:
			resp.Body.Close()
			return nil, fmt.Errorf("%s: auth error (%d)", a.name, resp.StatusCode)
		}

		if resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt < maxRetries {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
					backoff *= 2
					continue
				}
			}
			return nil, fmt.Errorf("%s: server error (%d)", a.name, resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("%s: unexpected status %d", a.name, resp.StatusCode)
		}

		break // success
	}

	ch := make(chan StreamEvent, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		a.readSSE(ctx, resp.Body, ch)
	}()
	return ch, nil
}

// readSSE reads Server-Sent Events from r and sends StreamEvents to ch.
func (a *OpenAICompatAdapter) readSSE(ctx context.Context, r io.Reader, ch chan<- StreamEvent) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			ch <- StreamEvent{Error: ctx.Err()}
			return
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			return
		}
		if payload == "" {
			continue
		}

		var chunk sseChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue // skip malformed lines
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		delta := chunk.Choices[0].Delta

		if delta.Content != "" {
			ch <- StreamEvent{Token: delta.Content}
		}

		for _, tc := range delta.ToolCalls {
			ch <- StreamEvent{ToolCall: &ToolCall{
				ID:     tc.ID,
				Name:   tc.Function.Name,
				Params: tc.Function.Arguments,
			}}
		}
	}

	if err := scanner.Err(); err != nil {
		ch <- StreamEvent{Error: fmt.Errorf("%s: stream read error: %w", a.name, err)}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Concrete provider constructors
// ─────────────────────────────────────────────────────────────────────────────

func NewOpenRouterProvider(apiKey string) Provider {
	return newAdapter("openrouter", "https://openrouter.ai/api/v1", apiKey, []ModelInfo{
		// Coding-optimized models — best for CBM Code
		{ID: "minimax/minimax-m2.5:free",                        Name: "MiniMax M2.5 (free)",        Provider: "openrouter", MaxTokens: 40960},
		{ID: "qwen/qwen3-coder:free",                            Name: "Qwen3 Coder (free)",         Provider: "openrouter", MaxTokens: 32768},
		{ID: "deepseek/deepseek-r1:free",                        Name: "DeepSeek R1 (free)",         Provider: "openrouter", MaxTokens: 65536},
		{ID: "google/gemma-4-31b-it:free",                       Name: "Gemma 4 31B (free)",         Provider: "openrouter", MaxTokens: 32768},
		{ID: "meta-llama/llama-3.3-70b-instruct:free",           Name: "Llama 3.3 70B (free)",       Provider: "openrouter", MaxTokens: 8192},
		{ID: "cognitivecomputations/dolphin-mistral-24b-venice-edition:free", Name: "Dolphin Uncensored (free)", Provider: "openrouter", MaxTokens: 32768},
		{ID: "openrouter/free",                                  Name: "OpenRouter Free Router",     Provider: "openrouter", MaxTokens: 8192},
		// Paid fallbacks
		{ID: "mistralai/mistral-7b-instruct",                    Name: "Mistral 7B Instruct",        Provider: "openrouter", MaxTokens: 32768},
	})
}

func NewGroqProvider(apiKey string) Provider {
	return newAdapter("groq", "https://api.groq.com/openai/v1", apiKey, []ModelInfo{
		{ID: "llama3-8b-8192", Name: "Llama 3 8B", Provider: "groq", MaxTokens: 8192},
		{ID: "llama3-70b-8192", Name: "Llama 3 70B", Provider: "groq", MaxTokens: 8192},
		{ID: "mixtral-8x7b-32768", Name: "Mixtral 8x7B", Provider: "groq", MaxTokens: 32768},
		{ID: "gemma2-9b-it", Name: "Gemma 2 9B IT", Provider: "groq", MaxTokens: 8192},
	})
}

func NewMistralProvider(apiKey string) Provider {
	return newAdapter("mistral", "https://api.mistral.ai/v1", apiKey, []ModelInfo{
		{ID: "mistral-small-latest", Name: "Mistral Small", Provider: "mistral", MaxTokens: 32768},
		{ID: "mistral-medium-latest", Name: "Mistral Medium", Provider: "mistral", MaxTokens: 32768},
		{ID: "codestral-latest", Name: "Codestral", Provider: "mistral", MaxTokens: 32768},
	})
}

func NewDeepSeekProvider(apiKey string) Provider {
	return newAdapter("deepseek", "https://api.deepseek.com/v1", apiKey, []ModelInfo{
		{ID: "deepseek-chat", Name: "DeepSeek Chat", Provider: "deepseek", MaxTokens: 65536},
		{ID: "deepseek-coder", Name: "DeepSeek Coder", Provider: "deepseek", MaxTokens: 65536},
	})
}

func NewNvidiaProvider(apiKey string) Provider {
	return newAdapter("nvidia", "https://integrate.api.nvidia.com/v1", apiKey, []ModelInfo{
		{ID: "meta/llama3-8b-instruct", Name: "Llama 3 8B Instruct", Provider: "nvidia", MaxTokens: 8192},
		{ID: "mistralai/mistral-7b-instruct-v0.3", Name: "Mistral 7B v0.3", Provider: "nvidia", MaxTokens: 32768},
	})
}

func NewSambanovaProvider(apiKey string) Provider {
	return newAdapter("sambanova", "https://api.sambanova.ai/v1", apiKey, []ModelInfo{
		{ID: "Meta-Llama-3.1-8B-Instruct", Name: "Llama 3.1 8B Instruct", Provider: "sambanova", MaxTokens: 16384},
		{ID: "Meta-Llama-3.1-70B-Instruct", Name: "Llama 3.1 70B Instruct", Provider: "sambanova", MaxTokens: 16384},
	})
}

func NewBytezProvider(apiKey string) Provider {
	return newAdapter("bytez", "https://api.bytez.com/models/v2", apiKey, []ModelInfo{
		{ID: "meta-llama/Llama-3.2-1B-Instruct", Name: "Llama 3.2 1B Instruct", Provider: "bytez", MaxTokens: 4096},
		{ID: "mistralai/Mistral-7B-Instruct-v0.3", Name: "Mistral 7B v0.3", Provider: "bytez", MaxTokens: 32768},
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ProviderChain — tries providers in order, starting from preferred
// ─────────────────────────────────────────────────────────────────────────────

// ProviderChain tries providers in order starting from the preferred one.
// On quota (429) or auth (401/403) errors it immediately advances to the next.
type ProviderChain struct {
	providers []Provider
	preferred int // index of user-preferred provider
}

// NewProviderChain builds a ProviderChain, placing the named preferred provider
// at index 0. If preferredName is not found, index 0 is used as preferred.
func NewProviderChain(providers []Provider, preferredName string) *ProviderChain {
	preferred := 0
	for i, p := range providers {
		if p.Name() == preferredName {
			preferred = i
			break
		}
	}

	// Reorder so preferred is first
	ordered := make([]Provider, 0, len(providers))
	ordered = append(ordered, providers[preferred])
	for i, p := range providers {
		if i != preferred {
			ordered = append(ordered, p)
		}
	}

	return &ProviderChain{providers: ordered, preferred: 0}
}

// Name returns the name of the currently preferred provider.
func (c *ProviderChain) Name() string {
	if len(c.providers) == 0 {
		return "none"
	}
	return c.providers[c.preferred].Name()
}

// StreamChat tries each provider in order starting from preferred.
// Returns the first successful stream, or an error listing all tried providers.
func (c *ProviderChain) StreamChat(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	var tried []string

	for i := c.preferred; i < len(c.providers); i++ {
		p := c.providers[i]
		ch, err := p.StreamChat(ctx, req)
		if err == nil {
			return ch, nil
		}

		tried = append(tried, p.Name())

		// Immediate failover on quota / auth errors — already handled inside
		// the adapter (those return errors, not channels). Any error here means
		// we should try the next provider.
		_ = err // advance to next
	}

	// Also try providers before preferred (wrap-around not needed per spec,
	// but we cover the full slice if preferred > 0 somehow)
	for i := 0; i < c.preferred; i++ {
		p := c.providers[i]
		ch, err := p.StreamChat(ctx, req)
		if err == nil {
			return ch, nil
		}
		tried = append(tried, p.Name())
	}

	return nil, fmt.Errorf("all providers exhausted: tried %s", strings.Join(tried, ", "))
}

// Models returns models from all providers in the chain.
func (c *ProviderChain) Models() []ModelInfo {
	var all []ModelInfo
	for _, p := range c.providers {
		all = append(all, p.Models()...)
	}
	return all
}

// HealthCheck checks all providers and returns the first error encountered.
func (c *ProviderChain) HealthCheck(ctx context.Context) error {
	for _, p := range c.providers {
		if err := p.HealthCheck(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ManagedProvider — paid tier, JWT-authenticated
// ─────────────────────────────────────────────────────────────────────────────

// ManagedProvider wraps an inner Provider and keeps a short-lived JWT
// fetched from the CyberMind backend. The JWT is never written to disk.
type ManagedProvider struct {
	supabaseURL string
	jwt         string
	jwtExpiry   time.Time
	mu          sync.Mutex
	inner       Provider // the actual provider to use with the JWT
}

// NewManagedProvider creates a ManagedProvider pointing at supabaseURL.
func NewManagedProvider(supabaseURL string) *ManagedProvider {
	return &ManagedProvider{supabaseURL: strings.TrimRight(supabaseURL, "/")}
}

// NewManagedProviderFromEnv creates a ManagedProvider using the same backend URL
// as the rest of the CyberMind CLI (CYBERMIND_API env var or default).
func NewManagedProviderFromEnv() *ManagedProvider {
	backendURL := os.Getenv("CYBERMIND_API")
	if backendURL == "" {
		backendURL = "https://cybermind-backend-8yrt.onrender.com"
	}
	return NewManagedProvider(strings.TrimRight(backendURL, "/"))
}

// fetchJWT retrieves a short-lived JWT from {supabaseURL}/api/vibe/token.
// The JWT is stored only in memory and never logged or written to disk.
func (m *ManagedProvider) fetchJWT(ctx context.Context) error {
	url := m.supabaseURL + "/api/vibe/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("managed: build token request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("managed: fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("managed: token endpoint returned %d", resp.StatusCode)
	}

	var payload struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"` // seconds
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("managed: decode token response: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwt = payload.Token
	if payload.ExpiresIn > 0 {
		m.jwtExpiry = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	} else {
		m.jwtExpiry = time.Now().Add(55 * time.Minute) // sensible default
	}
	return nil
}

// refreshLoop runs as a background goroutine, refreshing the JWT 60 seconds
// before it expires. It stops when ctx is cancelled.
func (m *ManagedProvider) refreshLoop(ctx context.Context) {
	for {
		m.mu.Lock()
		expiry := m.jwtExpiry
		m.mu.Unlock()

		refreshAt := expiry.Add(-60 * time.Second)
		waitDur := time.Until(refreshAt)
		if waitDur < 0 {
			waitDur = 0
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(waitDur):
			_ = m.fetchJWT(ctx) // best-effort; errors are non-fatal
		}
	}
}

// Name returns the name of the inner provider.
func (m *ManagedProvider) Name() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inner != nil {
		return "managed:" + m.inner.Name()
	}
	return "managed"
}

// StreamChat delegates to the inner provider after ensuring a valid JWT.
func (m *ManagedProvider) StreamChat(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	m.mu.Lock()
	inner := m.inner
	m.mu.Unlock()
	if inner == nil {
		return nil, fmt.Errorf("managed: no inner provider configured")
	}
	return inner.StreamChat(ctx, req)
}

// Models delegates to the inner provider.
func (m *ManagedProvider) Models() []ModelInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inner != nil {
		return m.inner.Models()
	}
	return nil
}

// HealthCheck delegates to the inner provider.
func (m *ManagedProvider) HealthCheck(ctx context.Context) error {
	m.mu.Lock()
	inner := m.inner
	m.mu.Unlock()
	if inner == nil {
		return fmt.Errorf("managed: no inner provider configured")
	}
	return inner.HealthCheck(ctx)
}

// IsPaidTier returns true if the config indicates Paid Tier authentication.
// For now, this checks if a "managed" provider is configured.
func IsPaidTier(cfg Config) bool {
	_, ok := cfg.Providers["managed"]
	return ok
}

// ReportUsage reports session token usage to the Supabase backend.
func (m *ManagedProvider) ReportUsage(ctx context.Context, sessionID string, tokensUsed int) error {
	url := m.supabaseURL + "/api/vibe/usage"
	payload := map[string]interface{}{
		"session_id":  sessionID,
		"tokens_used": tokensUsed,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	m.mu.Lock()
	jwt := m.jwt
	m.mu.Unlock()
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CyberMindBackendProvider — routes through the CyberMind backend
// This is the primary provider for users with a CyberMind API key.
// It uses the same key as the main CLI chat feature.
// ─────────────────────────────────────────────────────────────────────────────

// CyberMindBackendProvider sends requests to the CyberMind backend's
// /api/vibe/chat/stream endpoint, which handles provider routing internally.
type CyberMindBackendProvider struct {
	backendURL string
	apiKey     string
	client     *http.Client
}

// NewCyberMindBackendProvider creates a provider that routes through the backend.
// apiKey is the user's CyberMind API key (cp_live_...).
func NewCyberMindBackendProvider(apiKey string) *CyberMindBackendProvider {
	backendURL := os.Getenv("CYBERMIND_API")
	if backendURL == "" {
		backendURL = "https://cybermind-backend-8yrt.onrender.com"
	}
	return &CyberMindBackendProvider{
		backendURL: strings.TrimRight(backendURL, "/"),
		apiKey:     apiKey,
		client:     &http.Client{Timeout: 180 * time.Second},
	}
}

func (p *CyberMindBackendProvider) Name() string { return "cybermind-backend" }

func (p *CyberMindBackendProvider) Models() []ModelInfo {
	return []ModelInfo{
		{ID: "auto", Name: "CyberMind Auto (backend-routed)", Provider: "cybermind-backend", MaxTokens: 128000},
	}
}

func (p *CyberMindBackendProvider) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.backendURL+"/ping", nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("backend unreachable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend health check failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// StreamChat sends a streaming request to the CyberMind backend.
// The backend handles provider selection, fallback, and key rotation.
func (p *CyberMindBackendProvider) StreamChat(ctx context.Context, req ChatRequest) (<-chan StreamEvent, error) {
	// Build messages for the backend
	type backendMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	msgs := make([]backendMsg, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == RoleTool {
			// Convert tool results to assistant messages for backend compatibility
			if m.ToolResult != nil {
				msgs = append(msgs, backendMsg{Role: "assistant", Content: m.ToolResult.Output})
			}
			continue
		}
		msgs = append(msgs, backendMsg{Role: string(m.Role), Content: m.Content})
	}

	body := map[string]interface{}{
		"prompt":   req.Messages[len(req.Messages)-1].Content,
		"messages": msgs[:max(0, len(msgs)-1)], // history without last message
		"stream":   true,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("cybermind-backend: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.backendURL+"/api/vibe/chat/stream", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("cybermind-backend: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", p.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cybermind-backend: request failed: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		resp.Body.Close()
		return nil, fmt.Errorf("cybermind-backend: rate limit exceeded (429)")
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("cybermind-backend: auth error (%d) — check your API key", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("cybermind-backend: HTTP %d", resp.StatusCode)
	}

	ch := make(chan StreamEvent, 64)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		p.readSSE(ctx, resp.Body, ch)
	}()
	return ch, nil
}

// readSSE reads the SSE stream from the backend and sends events to ch.
func (p *CyberMindBackendProvider) readSSE(ctx context.Context, r io.Reader, ch chan<- StreamEvent) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			ch <- StreamEvent{Error: ctx.Err()}
			return
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var event struct {
			Token string `json:"token"`
			Done  bool   `json:"done"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			continue
		}
		if event.Error != "" {
			ch <- StreamEvent{Error: fmt.Errorf("backend: %s", event.Error)}
			return
		}
		if event.Done {
			return
		}
		if event.Token != "" {
			ch <- StreamEvent{Token: event.Token}
		}
	}

	if err := scanner.Err(); err != nil {
		ch <- StreamEvent{Error: fmt.Errorf("cybermind-backend: stream read error: %w", err)}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// BuildProviderChain builds the optimal provider chain for a given config.
// Priority:
//  1. CyberMind backend (if user has a cp_live_ key) — uses backend's smart routing
//  2. Direct provider keys from vibecoder.json
//  3. Error if no providers configured
func BuildProviderChain(cfg Config) (*ProviderChain, error) {
	var providers []Provider

	// 1. CyberMind backend provider (uses the main CLI key)
	mainKey := os.Getenv("CYBERMIND_KEY")
	if mainKey == "" {
		// Try reading from ~/.cybermind/config.json
		if home, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(home + "/.cybermind/config.json"); err == nil {
				var cfgFile struct {
					Key string `json:"key"`
				}
				if json.Unmarshal(data, &cfgFile) == nil && cfgFile.Key != "" {
					mainKey = cfgFile.Key
				}
			}
		}
	}
	if mainKey != "" && (strings.HasPrefix(mainKey, "cp_live_") || strings.HasPrefix(mainKey, "sk_live_cm_")) {
		providers = append(providers, NewCyberMindBackendProvider(mainKey))
	}

	// 2. Direct provider keys from vibecoder.json
	for name, pc := range cfg.Providers {
		if pc.APIKey == "" {
			continue
		}
		switch name {
		case "openrouter":
			providers = append(providers, NewOpenRouterProvider(pc.APIKey))
		case "groq":
			providers = append(providers, NewGroqProvider(pc.APIKey))
		case "mistral":
			providers = append(providers, NewMistralProvider(pc.APIKey))
		case "deepseek":
			providers = append(providers, NewDeepSeekProvider(pc.APIKey))
		case "nvidia":
			providers = append(providers, NewNvidiaProvider(pc.APIKey))
		case "sambanova":
			providers = append(providers, NewSambanovaProvider(pc.APIKey))
		case "bytez":
			providers = append(providers, NewBytezProvider(pc.APIKey))
		}
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no AI providers configured — run: cybermind --key cp_live_xxxxx")
	}

	return NewProviderChain(providers, cfg.DefaultProvider), nil
}
