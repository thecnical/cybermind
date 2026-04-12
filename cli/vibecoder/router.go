package vibecoder

import "strings"

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type RouterDecision struct {
	Provider   string
	Model      string
	Reason     string
	Complexity ComplexityClass
}

type ModelRef struct {
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
}

type RouterConfig struct {
	AutoRouting         bool      `json:"auto_routing"`
	LowComplexityModel  ModelRef  `json:"low_complexity_model"`
	HighComplexityModel ModelRef  `json:"high_complexity_model"`
	OverrideModel       *ModelRef `json:"override_model,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Task types & capability matrix
// ─────────────────────────────────────────────────────────────────────────────

type TaskType string

const (
	TaskComplexReasoning TaskType = "complex_reasoning"
	TaskFastCodegen      TaskType = "fast_codegen"
	TaskUICSS            TaskType = "ui_css"
	TaskLongContext      TaskType = "long_context"
	TaskMobile           TaskType = "mobile"
	TaskSecurity         TaskType = "security"
	TaskSimpleEdits      TaskType = "simple_edits"
	TaskDocs             TaskType = "docs"
	TaskVision           TaskType = "vision"
)

// ModelCapabilityMatrix maps task types to recommended model refs.
var ModelCapabilityMatrix = map[TaskType]ModelRef{
	TaskComplexReasoning: {Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
	TaskFastCodegen:      {Provider: "groq", ModelID: "llama3-8b-8192"},
	TaskUICSS:            {Provider: "openrouter", ModelID: "google/gemma-3-27b-it:free"},
	TaskLongContext:      {Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
	TaskMobile:           {Provider: "groq", ModelID: "llama3-70b-8192"},
	TaskSecurity:         {Provider: "openrouter", ModelID: "deepseek/deepseek-r1"},
	TaskSimpleEdits:      {Provider: "groq", ModelID: "llama3-8b-8192"},
	TaskDocs:             {Provider: "mistral", ModelID: "mistral-small-latest"},
	TaskVision:           {Provider: "openrouter", ModelID: "google/gemma-3-27b-it:free"},
}

// ─────────────────────────────────────────────────────────────────────────────
// Model profiles
// ─────────────────────────────────────────────────────────────────────────────

type ModelProfile string

const (
	ProfileSpeed    ModelProfile = "speed"
	ProfileQuality  ModelProfile = "quality"
	ProfileBalanced ModelProfile = "balanced"
	ProfileFreeOnly ModelProfile = "free-only"
)

// ApplyProfile adjusts RouterConfig based on the selected profile.
func ApplyProfile(cfg *RouterConfig, profile ModelProfile) {
	switch profile {
	case ProfileSpeed:
		cfg.LowComplexityModel = ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"}
		cfg.HighComplexityModel = ModelRef{Provider: "groq", ModelID: "llama3-70b-8192"}
	case ProfileQuality:
		cfg.LowComplexityModel = ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"}
		cfg.HighComplexityModel = ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"}
	case ProfileBalanced:
		cfg.LowComplexityModel = ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"}
		cfg.HighComplexityModel = ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"}
	case ProfileFreeOnly:
		cfg.LowComplexityModel = ModelRef{Provider: "openrouter", ModelID: "meta-llama/llama-3-8b-instruct:free"}
		cfg.HighComplexityModel = ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1:free"}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SmartRouter
// ─────────────────────────────────────────────────────────────────────────────

type SmartRouter struct {
	config RouterConfig
	chain  *ProviderChain
}

func NewSmartRouter(config RouterConfig, chain *ProviderChain) *SmartRouter {
	return &SmartRouter{config: config, chain: chain}
}

// reasoningKeywords is the set of keywords that signal high-complexity reasoning.
var reasoningKeywords = []string{
	"refactor", "architect", "explain why", "debug", "optimize",
	"redesign", "analyze", "performance", "security", "migrate",
}

// containsReasoningKeywords returns true if prompt contains any reasoning keyword.
func containsReasoningKeywords(prompt string) bool {
	lower := strings.ToLower(prompt)
	for _, kw := range reasoningKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// classify scores the prompt + session and returns a ComplexityClass.
func (r *SmartRouter) classify(prompt string, s *Session) ComplexityClass {
	score := 0
	if estimateTokens(prompt) > 500 {
		score += 3
	}
	if len(s.OpenFiles) >= 3 {
		score += 2
	}
	if containsReasoningKeywords(prompt) {
		score += 2
	}
	if s.InteractMode == InteractModeAgent && s.EffortLevel == EffortMax {
		score += 2
	}
	if score >= 5 {
		return HighComplexity
	}
	return LowComplexity
}

// Route returns a RouterDecision for the given prompt and session.
func (r *SmartRouter) Route(prompt string, s *Session) RouterDecision {
	// Override takes precedence over everything.
	if r.config.OverrideModel != nil {
		return RouterDecision{
			Provider:   r.config.OverrideModel.Provider,
			Model:      r.config.OverrideModel.ModelID,
			Reason:     "override model set",
			Complexity: r.classify(prompt, s),
		}
	}

	complexity := r.classify(prompt, s)

	var ref ModelRef
	var reason string

	switch complexity {
	case HighComplexity:
		ref = r.config.HighComplexityModel
		if ref.Provider == "" {
			ref = ModelRef{Provider: "openrouter", ModelID: "deepseek/deepseek-r1"}
		}
		reason = "high complexity prompt"
	default:
		ref = r.config.LowComplexityModel
		if ref.Provider == "" {
			ref = ModelRef{Provider: "groq", ModelID: "llama3-8b-8192"}
		}
		reason = "low complexity prompt"
	}

	return RouterDecision{
		Provider:   ref.Provider,
		Model:      ref.ModelID,
		Reason:     reason,
		Complexity: complexity,
	}
}
