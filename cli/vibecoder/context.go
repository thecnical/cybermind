package vibecoder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ContextBudget defines the allocation of context window tokens.
type ContextBudget struct {
	ConversationPct float64 // 60%
	MemoryPct       float64 // 10%
	SemanticPct     float64 // 20%
	PinnedPct       float64 // 10%
}

// DefaultContextBudget is the standard context allocation.
var DefaultContextBudget = ContextBudget{
	ConversationPct: 0.60,
	MemoryPct:       0.10,
	SemanticPct:     0.20,
	PinnedPct:       0.10,
}

// CyberMindMemory manages the CYBERMIND.md project memory file.
type CyberMindMemory struct {
	workspaceRoot string
	path          string
}

// NewCyberMindMemory creates a CyberMindMemory for the given workspace.
func NewCyberMindMemory(workspaceRoot string) *CyberMindMemory {
	return &CyberMindMemory{
		workspaceRoot: workspaceRoot,
		path:          filepath.Join(workspaceRoot, "CYBERMIND.md"),
	}
}

// Load reads CYBERMIND.md content. Returns "" if not found.
func (m *CyberMindMemory) Load() string {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return ""
	}
	return string(data)
}

// Save writes content to CYBERMIND.md atomically.
func (m *CyberMindMemory) Save(content string) error {
	return atomicWrite(m.path, []byte(content))
}

// Init generates a CYBERMIND.md from workspace analysis.
// Detects project type, tech stack, build commands, conventions.
func (m *CyberMindMemory) Init(workspaceRoot string) (string, error) {
	var sb strings.Builder
	sb.WriteString("# CYBERMIND.md — Project Memory\n\n")

	// Detect project type
	projectType := detectProjectType(workspaceRoot)
	sb.WriteString(fmt.Sprintf("## Project Type\n%s\n\n", projectType))

	// Detect tech stack
	stack := detectTechStack(workspaceRoot)
	sb.WriteString("## Tech Stack\n")
	for _, s := range stack {
		sb.WriteString("- " + s + "\n")
	}
	sb.WriteString("\n")

	// Build commands
	buildCmds := detectBuildCommands(workspaceRoot)
	sb.WriteString("## Build Commands\n")
	for _, cmd := range buildCmds {
		sb.WriteString("- `" + cmd + "`\n")
	}
	sb.WriteString("\n")

	sb.WriteString("## Conventions\n")
	sb.WriteString("- (Add project-specific conventions here)\n\n")

	content := sb.String()
	return content, m.Save(content)
}

func detectProjectType(root string) string {
	checks := []struct{ file, typ string }{
		{"go.mod", "Go module"},
		{"package.json", "Node.js"},
		{"Cargo.toml", "Rust"},
		{"pyproject.toml", "Python"},
		{"requirements.txt", "Python"},
		{"pom.xml", "Java/Maven"},
		{"build.gradle", "Java/Gradle"},
		{"Gemfile", "Ruby"},
	}
	for _, c := range checks {
		if _, err := os.Stat(filepath.Join(root, c.file)); err == nil {
			return c.typ
		}
	}
	return "Unknown"
}

func detectTechStack(root string) []string {
	var stack []string
	files := map[string]string{
		"go.mod":              "Go",
		"package.json":        "Node.js/JavaScript",
		"tsconfig.json":       "TypeScript",
		"Cargo.toml":          "Rust",
		"requirements.txt":    "Python",
		"Dockerfile":          "Docker",
		"docker-compose.yml":  "Docker Compose",
		".github":             "GitHub Actions",
	}
	for file, tech := range files {
		if _, err := os.Stat(filepath.Join(root, file)); err == nil {
			stack = append(stack, tech)
		}
	}
	return stack
}

func detectBuildCommands(root string) []string {
	var cmds []string
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		cmds = append(cmds, "go build ./...", "go test ./...")
	}
	if _, err := os.Stat(filepath.Join(root, "package.json")); err == nil {
		cmds = append(cmds, "npm install", "npm run build", "npm test")
	}
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err == nil {
		cmds = append(cmds, "make", "make test")
	}
	return cmds
}

// CompressContext summarizes old conversation turns and appends to CYBERMIND.md.
// Preserves last 6 messages verbatim.
func CompressContext(s *Session, memory *CyberMindMemory) {
	if len(s.History) < 6 {
		return
	}

	// Keep last 6 messages verbatim
	keepFrom := len(s.History) - 6
	toCompress := s.History[:keepFrom]

	// Build summary
	var sb strings.Builder
	sb.WriteString("\n## Compressed Context\n")
	sb.WriteString(fmt.Sprintf("(Summarized %d messages)\n\n", len(toCompress)))
	for _, msg := range toCompress {
		if msg.Role == RoleUser {
			sb.WriteString("- User: " + truncateStr2(msg.Content, 100) + "\n")
		}
	}

	existing := memory.Load()
	_ = memory.Save(existing + sb.String())

	// Truncate history
	s.History = s.History[keepFrom:]
	s.TokensUsed = 0
	for _, msg := range s.History {
		s.TokensUsed += msg.Tokens
	}
}

func truncateStr2(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
