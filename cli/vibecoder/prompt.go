package vibecoder

import "strings"

// SystemPromptBuilder assembles the system prompt for a given session.
type SystemPromptBuilder struct {
	session  *Session
	memory   *CyberMindMemory
	profile  *BrainProfile
	skills   *SkillRegistry
}

func NewSystemPromptBuilder(session *Session, memory *CyberMindMemory) *SystemPromptBuilder {
	return &SystemPromptBuilder{session: session, memory: memory}
}

// SetSkills wires the skill registry for skill adherence injection.
func (b *SystemPromptBuilder) SetSkills(skills *SkillRegistry) {
	b.skills = skills
}

// Build assembles the full system prompt.
func (b *SystemPromptBuilder) Build() string {
	var parts []string

	parts = append(parts, "You are CyberMind Neural, an expert AI coding assistant.")
	parts = append(parts, "Workspace: "+b.session.WorkspaceRoot)

	// Memory — CYBERMIND.md project context
	if b.memory != nil {
		if mem := b.memory.Load(); mem != "" {
			parts = append(parts, "\n## Project Memory (CYBERMIND.md)\n"+mem)
		}
	}

	// Skill adherence — inject available skills so AI knows what's available
	if b.skills != nil {
		allSkills := b.skills.All()
		if len(allSkills) > 0 {
			var sb strings.Builder
			sb.WriteString("\n## Available Skills\n")
			sb.WriteString("You have access to these skills (invoked via /skill-name):\n")
			for _, s := range allSkills {
				sb.WriteString("- **/" + s.Meta.Name + "**: " + s.Meta.Description + "\n")
			}
			sb.WriteString("\nWhen a skill is invoked, follow its instructions precisely and completely.")
			parts = append(parts, sb.String())
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
