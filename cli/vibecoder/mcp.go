package vibecoder

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// MCPServerConfig holds configuration for a single MCP server.
type MCPServerConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Enabled bool     `json:"enabled"`
}

// MCPConfig holds the full MCP configuration.
type MCPConfig struct {
	Servers []MCPServerConfig `json:"servers"`
}

// LoadMCPConfig reads ~/.cybermind/mcp.json.
func LoadMCPConfig() (MCPConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return MCPConfig{}, err
	}
	path := filepath.Join(home, ".cybermind", "mcp.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return MCPConfig{}, nil
	}
	if err != nil {
		return MCPConfig{}, err
	}
	var cfg MCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return MCPConfig{}, err
	}
	return cfg, nil
}

// PreConfiguredMCPServers returns the list of pre-configured MCP servers.
func PreConfiguredMCPServers() []MCPServerConfig {
	return []MCPServerConfig{
		{Name: "21st-magic-ui", Command: "npx", Args: []string{"@21st-dev/magic-mcp"}, Enabled: false},
		{Name: "figma", Command: "npx", Args: []string{"figma-mcp"}, Enabled: false},
		{Name: "github", Command: "npx", Args: []string{"@modelcontextprotocol/server-github"}, Enabled: false},
		{Name: "playwright", Command: "npx", Args: []string{"@playwright/mcp"}, Enabled: false},
		{Name: "filesystem", Command: "npx", Args: []string{"@modelcontextprotocol/server-filesystem"}, Enabled: false},
		{Name: "fetch", Command: "npx", Args: []string{"@modelcontextprotocol/server-fetch"}, Enabled: false},
	}
}
