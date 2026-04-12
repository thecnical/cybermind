package vibecoder

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ProviderConfig holds per-provider settings.
type ProviderConfig struct {
	APIKey       string `json:"api_key"`
	DefaultModel string `json:"default_model"`
}

// Config is the full vibecoder configuration.
type Config struct {
	DefaultProvider         string                    `json:"default_provider"`
	DefaultModel            string                    `json:"default_model"`
	AutoRouting             bool                      `json:"auto_routing"`
	EditMode                EditMode                  `json:"edit_mode"`
	EffortLevel             EffortLevel               `json:"effort_level"`
	CommandTimeoutSecs      int                       `json:"command_timeout_secs"`
	ContextDepthLimit       int                       `json:"context_depth_limit"`
	CheckpointIntervalTurns int                       `json:"checkpoint_interval_turns"`
	AutoApproveReads        bool                      `json:"auto_approve_reads"`
	AutoApproveWrites       bool                      `json:"auto_approve_writes"`
	ShowWelcome             bool                      `json:"show_welcome"`
	Providers               map[string]ProviderConfig `json:"providers"`
}

// WhoAmIInfo holds display info for the --whoami flag.
type WhoAmIInfo struct {
	Tier      string
	Provider  string
	Model     string
	MaskedKey string
}

// ProviderInfo holds display info for the --providers flag.
type ProviderInfo struct {
	Name         string
	HasKey       bool
	DefaultModel string
}

// defaultConfig returns a Config populated with sensible defaults.
func defaultConfig() Config {
	return Config{
		DefaultProvider:         "openrouter",
		DefaultModel:            "mistralai/mistral-7b-instruct",
		AutoRouting:             true,
		EditMode:                EditModeGuard,
		EffortLevel:             EffortMedium,
		CommandTimeoutSecs:      30,
		ContextDepthLimit:       3,
		CheckpointIntervalTurns: 5,
		AutoApproveReads:        false,
		AutoApproveWrites:       false,
		ShowWelcome:             true,
		Providers:               map[string]ProviderConfig{},
	}
}

// ConfigFilePath returns the path to the global config file.
func ConfigFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cybermind", "vibecoder.json"), nil
}

// loadJSON reads a JSON file into cfg, merging only fields that are present.
// Missing file is silently ignored (returns nil).
func loadJSON(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}

// LoadConfig reads the global config then applies any project-level override.
// Returns sensible defaults when no config files exist.
func LoadConfig() (Config, error) {
	cfg := defaultConfig()

	// 1. Global config: ~/.cybermind/vibecoder.json
	globalPath, err := ConfigFilePath()
	if err == nil {
		if err2 := loadJSON(globalPath, &cfg); err2 != nil {
			return cfg, err2
		}
	}

	// 2. Project-level override: .vibecoder in cwd
	if cwd, err2 := os.Getwd(); err2 == nil {
		projectPath := filepath.Join(cwd, ".vibecoder")
		if err3 := loadJSON(projectPath, &cfg); err3 != nil {
			return cfg, err3
		}
	}

	// Ensure Providers map is never nil
	if cfg.Providers == nil {
		cfg.Providers = map[string]ProviderConfig{}
	}

	return cfg, nil
}

// SaveConfig writes cfg to ~/.cybermind/vibecoder.json using an atomic write
// and restricts file permissions to owner-only.
func SaveConfig(cfg Config) error {
	path, err := ConfigFilePath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := atomicWriteConfig(path, data); err != nil {
		return err
	}

	return nil
}

// SetAPIKey saves an API key for the given provider into the config file.
func SetAPIKey(provider, key string) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	pc := cfg.Providers[provider]
	pc.APIKey = key
	cfg.Providers[provider] = pc

	return SaveConfig(cfg)
}

// GetWhoAmI returns display info about the current config.
func GetWhoAmI(cfg *Config) WhoAmIInfo {
	maskedKey := "(not set)"
	if pc, ok := cfg.Providers[cfg.DefaultProvider]; ok {
		maskedKey = MaskAPIKey(pc.APIKey)
	}
	return WhoAmIInfo{
		Tier:      "free",
		Provider:  cfg.DefaultProvider,
		Model:     cfg.DefaultModel,
		MaskedKey: maskedKey,
	}
}

// MaskAPIKey returns "****<last4>" for non-empty keys, or "(not set)" for empty.
func MaskAPIKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	runes := []rune(key)
	if len(runes) <= 4 {
		return "****" + string(runes)
	}
	return "****" + string(runes[len(runes)-4:])
}

// ListProviders returns info about all configured providers.
func ListProviders(cfg *Config) []ProviderInfo {
	result := make([]ProviderInfo, 0, len(cfg.Providers))
	for name, pc := range cfg.Providers {
		result = append(result, ProviderInfo{
			Name:         name,
			HasKey:       pc.APIKey != "",
			DefaultModel: pc.DefaultModel,
		})
	}
	return result
}
