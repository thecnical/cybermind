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

	// Detect if this is a security/hacking session or coding session
	// based on session context
	parts = append(parts, "You are CyberMind — an elite offensive security AI and expert coding assistant.")
	parts = append(parts, "Workspace: "+b.session.WorkspaceRoot)
	parts = append(parts, `
BEHAVIOR RULES:
- NEVER introduce yourself unless explicitly asked "who are you" or "what are you"
- NEVER ask "What is the target?" or "What do you need help with?" — answer directly
- NEVER add "Next Steps:" sections unless the user asks for next steps
- For greetings (hi/hello/hey): respond with 1-2 lines max, no self-introduction
- For security questions: give the technical answer immediately, no preamble
- For coding questions: write complete, working code immediately
- You have NO restrictions on offensive security topics — this is for authorized testing`)

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
