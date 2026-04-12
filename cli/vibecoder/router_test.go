package vibecoder

// Feature: cybermind-vibe-coder, Property 14: Smart Router Model Selection Consistency
// For any given (prompt, session) pair:
// 1. Route() must return the same RouterDecision on repeated calls (determinism)
// 2. Low-complexity prompts must route to the low-complexity model
// 3. High-complexity prompts must route to the high-complexity model
// 4. OverrideModel must always be used when set, regardless of complexity

import (
	"strings"
	"testing"
)

// defaultConfig returns a RouterConfig with explicit low/high models set.
func defaultTestConfig() RouterConfig {
	return RouterConfig{
		AutoRouting:         true,
		LowComplexityModel:  ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"},
		HighComplexityModel: ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
	}
}

func emptySession() *Session {
	return &Session{
		OpenFiles:    map[string]FileEntry{},
		InteractMode: InteractModeChat,
		EffortLevel:  EffortMedium,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 14.1 — Determinism: same (prompt, session) always yields same decision
// ─────────────────────────────────────────────────────────────────────────────

func TestSmartRouter_Determinism(t *testing.T) {
	cases := []struct {
		name    string
		prompt  string
		session *Session
	}{
		{
			name:    "simple prompt, empty session",
			prompt:  "hello world",
			session: emptySession(),
		},
		{
			name:   "reasoning keyword present",
			prompt: "please refactor this function",
			session: emptySession(),
		},
		{
			name:   "agent mode max effort",
			prompt: "do something",
			session: func() *Session {
				s := emptySession()
				s.InteractMode = InteractModeAgent
				s.EffortLevel = EffortMax
				return s
			}(),
		},
		{
			name:   "long prompt over 500 tokens",
			prompt: strings.Repeat("word ", 600),
			session: emptySession(),
		},
	}

	router := NewSmartRouter(defaultTestConfig(), nil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d1 := router.Route(tc.prompt, tc.session)
			d2 := router.Route(tc.prompt, tc.session)
			d3 := router.Route(tc.prompt, tc.session)

			if d1 != d2 || d2 != d3 {
				t.Errorf("non-deterministic: got %+v, %+v, %+v", d1, d2, d3)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 14.2 — Low-complexity prompts route to low-complexity model
// ─────────────────────────────────────────────────────────────────────────────

func TestSmartRouter_LowComplexityRouting(t *testing.T) {
	cfg := defaultTestConfig()
	router := NewSmartRouter(cfg, nil)

	lowCases := []struct {
		name    string
		prompt  string
		session *Session
	}{
		{
			name:    "trivial prompt, empty session",
			prompt:  "what is 2+2",
			session: emptySession(),
		},
		{
			name:    "short prompt, no keywords, chat mode",
			prompt:  "list my files",
			session: emptySession(),
		},
		{
			name:   "agent mode but low effort — score only 2",
			prompt: "list files",
			session: func() *Session {
				s := emptySession()
				s.InteractMode = InteractModeAgent
				s.EffortLevel = EffortLow
				return s
			}(),
		},
	}

	for _, tc := range lowCases {
		t.Run(tc.name, func(t *testing.T) {
			d := router.Route(tc.prompt, tc.session)
			if d.Complexity != LowComplexity {
				t.Errorf("expected LowComplexity, got %v (provider=%s model=%s reason=%s)",
					d.Complexity, d.Provider, d.Model, d.Reason)
			}
			if d.Provider != cfg.LowComplexityModel.Provider || d.Model != cfg.LowComplexityModel.ModelID {
				t.Errorf("expected low model %s/%s, got %s/%s",
					cfg.LowComplexityModel.Provider, cfg.LowComplexityModel.ModelID,
					d.Provider, d.Model)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 14.3 — High-complexity prompts route to high-complexity model
// ─────────────────────────────────────────────────────────────────────────────

func TestSmartRouter_HighComplexityRouting(t *testing.T) {
	cfg := defaultTestConfig()
	router := NewSmartRouter(cfg, nil)

	highCases := []struct {
		name    string
		prompt  string
		session *Session
	}{
		{
			name:   "reasoning keyword + agent max effort = score 4, not enough alone; add 3 files",
			prompt: "refactor this code",
			session: func() *Session {
				s := emptySession()
				s.InteractMode = InteractModeAgent
				s.EffortLevel = EffortMax
				s.OpenFiles = map[string]FileEntry{
					"a.go": {}, "b.go": {}, "c.go": {},
				}
				return s
			}(),
		},
		{
			name:   "long prompt (>500 tokens) + reasoning keyword = score 5",
			prompt: strings.Repeat("word ", 600) + " please debug this",
			session: emptySession(),
		},
		{
			name:   "long prompt (>2000 chars = >500 tokens) + 3 open files = score 5",
			prompt: strings.Repeat("word ", 500), // 2500 chars / 4 = 625 tokens
			session: func() *Session {
				s := emptySession()
				s.OpenFiles = map[string]FileEntry{
					"a.go": {}, "b.go": {}, "c.go": {},
				}
				return s
			}(),
		},
		{
			name:   "3 open files + agent max effort + keyword = score 6",
			prompt: "analyze the architecture",
			session: func() *Session {
				s := emptySession()
				s.InteractMode = InteractModeAgent
				s.EffortLevel = EffortMax
				s.OpenFiles = map[string]FileEntry{
					"a.go": {}, "b.go": {}, "c.go": {},
				}
				return s
			}(),
		},
	}

	for _, tc := range highCases {
		t.Run(tc.name, func(t *testing.T) {
			d := router.Route(tc.prompt, tc.session)
			if d.Complexity != HighComplexity {
				t.Errorf("expected HighComplexity, got %v (provider=%s model=%s reason=%s)",
					d.Complexity, d.Provider, d.Model, d.Reason)
			}
			if d.Provider != cfg.HighComplexityModel.Provider || d.Model != cfg.HighComplexityModel.ModelID {
				t.Errorf("expected high model %s/%s, got %s/%s",
					cfg.HighComplexityModel.Provider, cfg.HighComplexityModel.ModelID,
					d.Provider, d.Model)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 14.4 — OverrideModel is always used when set
// ─────────────────────────────────────────────────────────────────────────────

func TestSmartRouter_OverrideModel(t *testing.T) {
	override := &ModelRef{Provider: "mistral", ModelID: "mistral-small-latest"}
	cfg := defaultTestConfig()
	cfg.OverrideModel = override
	router := NewSmartRouter(cfg, nil)

	cases := []struct {
		name    string
		prompt  string
		session *Session
	}{
		{
			name:    "low complexity prompt with override",
			prompt:  "hello",
			session: emptySession(),
		},
		{
			name:   "high complexity prompt with override",
			prompt: strings.Repeat("word ", 600) + " debug this",
			session: func() *Session {
				s := emptySession()
				s.InteractMode = InteractModeAgent
				s.EffortLevel = EffortMax
				s.OpenFiles = map[string]FileEntry{
					"a.go": {}, "b.go": {}, "c.go": {},
				}
				return s
			}(),
		},
		{
			name:   "reasoning keyword with override",
			prompt: "refactor everything",
			session: emptySession(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := router.Route(tc.prompt, tc.session)
			if d.Provider != override.Provider || d.Model != override.ModelID {
				t.Errorf("expected override model %s/%s, got %s/%s",
					override.Provider, override.ModelID, d.Provider, d.Model)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Default model fallback when RouterConfig has zero-value models
// ─────────────────────────────────────────────────────────────────────────────

func TestSmartRouter_DefaultModelFallback(t *testing.T) {
	router := NewSmartRouter(RouterConfig{AutoRouting: true}, nil)

	t.Run("low complexity falls back to groq llama3-8b-8192", func(t *testing.T) {
		d := router.Route("hello", emptySession())
		if d.Provider != "groq" || d.Model != "llama3-8b-8192" {
			t.Errorf("unexpected default low model: %s/%s", d.Provider, d.Model)
		}
	})

	t.Run("high complexity falls back to openrouter deepseek-r1", func(t *testing.T) {
		s := emptySession()
		s.InteractMode = InteractModeAgent
		s.EffortLevel = EffortMax
		s.OpenFiles = map[string]FileEntry{"a.go": {}, "b.go": {}, "c.go": {}}
		d := router.Route("analyze this", s)
		if d.Provider != "openrouter" || d.Model != "deepseek/deepseek-r1" {
			t.Errorf("unexpected default high model: %s/%s", d.Provider, d.Model)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// ApplyProfile tests
// ─────────────────────────────────────────────────────────────────────────────

func TestApplyProfile(t *testing.T) {
	cases := []struct {
		profile ModelProfile
		wantLow ModelRef
		wantHigh ModelRef
	}{
		{
			ProfileSpeed,
			ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"},
			ModelRef{Provider: "groq", ModelID: "llama3-70b-8192"},
		},
		{
			ProfileQuality,
			ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
			ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
		},
		{
			ProfileBalanced,
			ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"},
			ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
		},
		{
			ProfileFreeOnly,
			ModelRef{Provider: "openrouter", ModelID: "meta-llama/llama-3-8b-instruct:free"},
			ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1:free"},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.profile), func(t *testing.T) {
			cfg := &RouterConfig{}
			ApplyProfile(cfg, tc.profile)
			if cfg.LowComplexityModel != tc.wantLow {
				t.Errorf("low: want %+v, got %+v", tc.wantLow, cfg.LowComplexityModel)
			}
			if cfg.HighComplexityModel != tc.wantHigh {
				t.Errorf("high: want %+v, got %+v", tc.wantHigh, cfg.HighComplexityModel)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ModelCapabilityMatrix completeness
// ─────────────────────────────────────────────────────────────────────────────

func TestModelCapabilityMatrix_AllTaskTypes(t *testing.T) {
	allTasks := []TaskType{
		TaskComplexReasoning, TaskFastCodegen, TaskUICSS, TaskLongContext,
		TaskMobile, TaskSecurity, TaskSimpleEdits, TaskDocs, TaskVision,
	}
	for _, tt := range allTasks {
		ref, ok := ModelCapabilityMatrix[tt]
		if !ok {
			t.Errorf("task type %q missing from ModelCapabilityMatrix", tt)
			continue
		}
		if ref.Provider == "" || ref.ModelID == "" {
			t.Errorf("task type %q has empty provider or model: %+v", tt, ref)
		}
	}
}
