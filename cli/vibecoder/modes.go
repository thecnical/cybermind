package vibecoder

// Task 25: Dual mode system (Chat Mode / Agent Mode)

// SwitchMode switches the session's interact mode.
// If switching from Agent to Chat, it's the caller's responsibility to
// complete any in-progress tool call before calling this.
func (s *Session) SwitchMode(mode InteractMode) {
	s.InteractMode = mode
}

// SwitchEditMode switches the session's edit mode.
func (s *Session) SwitchEditMode(mode EditMode) {
	s.EditMode = mode
}

// Task 26: Debug mode

// ActivateDebugMode enables debug mode for the session.
func (s *Session) ActivateDebugMode() {
	s.DebugMode = true
}

// DeactivateDebugMode disables debug mode.
func (s *Session) DeactivateDebugMode() {
	s.DebugMode = false
}

// DebugSystemPrompt returns the system prompt suffix for debug mode.
func DebugSystemPrompt() string {
	return `
You are in DEBUG MODE. Your task is to:
1. Analyze the provided code or error description
2. Identify ALL errors, bugs, and issues
3. For each issue, provide a Diff_Preview showing before/after
4. Include a plain-language explanation of what was wrong and why the fix works
5. If no errors found, report "No errors found" and suggest optimizations
6. If confidence is low, present multiple candidate fixes and ask for clarification
`
}

// Task 29: Effort level system

// SetEffortLevel updates the session's effort level.
func (s *Session) SetEffortLevel(level EffortLevel) {
	s.EffortLevel = level
}

// EffortSystemPromptSuffix returns the system prompt suffix for the given effort level.
func EffortSystemPromptSuffix(level EffortLevel) string {
	switch level {
	case EffortLow:
		return "\nRespond concisely. Single-pass only. Minimal tool calls."
	case EffortMax:
		return "\nUse multi-step planning before execution. Extended reasoning. Use as many tool calls as needed."
	default:
		return "\nStandard response with tool calls as needed."
	}
}
