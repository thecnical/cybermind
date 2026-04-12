package vibecoder

import (
	"encoding/json"
	"time"
)

// Ensure json import is used
var _ = json.Marshal

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type EditMode string

const (
	EditModeGuard     EditMode = "guard"
	EditModeAutoEdit  EditMode = "auto_edit"
	EditModeBlueprint EditMode = "blueprint"
	EditModeAutopilot EditMode = "autopilot"
	EditModeUnleashed EditMode = "unleashed"
)

type InteractMode string

const (
	InteractModeChat  InteractMode = "chat"
	InteractModeAgent InteractMode = "agent"
)

type EffortLevel string

const (
	EffortLow    EffortLevel = "low"
	EffortMedium EffortLevel = "medium"
	EffortMax    EffortLevel = "max"
)

type ComplexityClass int

const (
	LowComplexity  ComplexityClass = 0
	HighComplexity ComplexityClass = 1
)

type Message struct {
	Role       Role        `json:"role"`
	Content    string      `json:"content"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolResult *ToolResult `json:"tool_result,omitempty"`
	Timestamp  time.Time   `json:"timestamp"`
	Tokens     int         `json:"tokens"`
}

type FileEntry struct {
	Path        string    `json:"path"`
	Content     string    `json:"content"`
	Hash        string    `json:"hash"`
	AddedAt     time.Time `json:"added_at"`
	StaleWarned bool      `json:"stale_warned"`
}

type FileSnapshot struct {
	Path       string `json:"path"`
	OldContent string `json:"old_content"`
}

type Session struct {
	ID            string               `json:"id"`
	WorkspaceRoot string               `json:"workspace_root"`
	History       []Message            `json:"history"`
	OpenFiles     map[string]FileEntry `json:"open_files"`
	EditMode      EditMode             `json:"edit_mode"`
	InteractMode  InteractMode         `json:"interact_mode"`
	EffortLevel   EffortLevel          `json:"effort_level"`
	DebugMode     bool                 `json:"debug_mode"`
	UndoStack     []FileSnapshot       `json:"undo_stack"`
	TokensUsed    int                  `json:"tokens_used"`
	MaxTokens     int                  `json:"max_tokens"`
}
