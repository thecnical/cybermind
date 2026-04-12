package vibecoder

import "strings"

// SystemPromptBuilder assembles the system prompt for a given session.
type SystemPromptBuilder struct {
	session *Session
	memory  *CyberMindMemory
	profile *BrainProfile
}

func NewSystemPromptBuilder(session *Session, memory *CyberMindMemory) *SystemPromptBuilder {
	return &SystemPromptBuilder{session: session, memory: memory}
}

// Build assembles the full system prompt.
func (b *SystemPromptBuilder) Build() string {
	var parts []string

	parts = append(parts, "You are CyberMind Neural, an expert AI coding assistant.")
	parts = append(parts, "Workspace: "+b.session.WorkspaceRoot)

	// Memory
	if b.memory != nil {
		if mem := b.memory.Load(); mem != "" {
			parts = append(parts, "\n## Project Memory\n"+mem)
		}
	}

	// Debug mode
	if b.session.DebugMode {
		parts = append(parts, DebugSystemPrompt())
	}

	// Effort level
	parts = append(parts, EffortSystemPromptSuffix(b.session.EffortLevel))

	// Web design principles (if web-related)
	if b.profile != nil {
		parts = append(parts, WebDesignPrinciplesPrompt())
	}

	return strings.Join(parts, "\n")
}

// SetProfile sets the brain profile for web-related prompts.
func (b *SystemPromptBuilder) SetProfile(profile *BrainProfile) {
	b.profile = profile
}
