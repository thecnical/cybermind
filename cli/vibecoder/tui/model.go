package tui

import (
	"context"
	"fmt"

	"cybermind-cli/vibecoder"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── Bubbletea message types ──────────────────────────────────────────────────

// TokenMsg carries a single streamed token from the AI.
type TokenMsg struct{ Token string }

// ToolStatusMsg carries a tool execution status update.
type ToolStatusMsg struct{ Tool, Action string }

// DiffReadyMsg carries a diff ready for display.
type DiffReadyMsg struct{ Diff vibecoder.FileDiff }

// ApprovalRequestMsg triggers the approval gate overlay.
type ApprovalRequestMsg struct{ Kind, Description string }

// IndexProgressMsg carries file indexer progress.
type IndexProgressMsg struct{ Done, Total int }

// ErrorMsg carries an error to display in the chat area.
type ErrorMsg struct{ Err error }

// StaleFileMsg is sent when a file in context has changed on disk.
type StaleFileMsg struct{ FilePath string }

// AgentDoneMsg is sent when the agent loop finishes a turn.
type AgentDoneMsg struct{ Err error }

// WarnMsg carries a warning from the agent loop.
type WarnMsg struct{ Text string }

// ─── UI modes ─────────────────────────────────────────────────────────────────

type UIMode int

const (
	UIModeWelcome  UIMode = iota
	UIModeSession
	UIModeSlashMenu
	UIModeRunning // agent loop is running — input blocked
)

// ─── Supporting types ─────────────────────────────────────────────────────────

// RenderedLine is a single line in the chat area with its style.
type RenderedLine struct {
	Content string
	Style   lipgloss.Style
}

// StatusBarState holds the values displayed in the NeuralBar.
type StatusBarState struct {
	InteractMode  string
	EditMode      string
	EffortLevel   string
	Model         string
	ContextPct    float64
	BgProcesses   int
	PermIndicator string
	Running       bool // true while agent loop is active
}

// DiffPreviewModel holds a diff to display in the session view.
type DiffPreviewModel struct {
	Diff    vibecoder.FileDiff
	Visible bool
}

// ApprovalGateModel holds a pending approval request.
type ApprovalGateModel struct {
	Kind        string
	Description string
	Visible     bool
}

// Backend holds the wired backend components for the TUI.
type Backend struct {
	AgentLoop    *vibecoder.AgentLoop
	FileIndexer  *vibecoder.FileIndexer
	Memory       *vibecoder.CyberMindMemory
	Skills       *vibecoder.SkillRegistry
	Hooks        *vibecoder.HookRegistry
	Orchestrator *vibecoder.SubagentOrchestrator
	// cancelLoop cancels the currently running agent loop goroutine.
	cancelLoop context.CancelFunc
}

// ─── VibeModel ────────────────────────────────────────────────────────────────

// VibeModel is the root bubbletea model for the Vibe Coder TUI.
type VibeModel struct {
	// layout
	width, height int
	mode          UIMode

	// session state
	session      *vibecoder.Session
	inputBuf     string
	inputHistory []string
	historyIdx   int
	scrollOffset int
	chatLines    []RenderedLine

	// welcome screen info
	welcomeInfo WelcomeInfo

	// backend (set via SetBackend after construction)
	backend *Backend

	// overlays
	slashMenu    SlashMenuModel
	diffPreview  *DiffPreviewModel
	approvalGate *ApprovalGateModel

	// status bar
	statusBar StatusBarState

	// theme
	theme Theme

	// program reference — set by main.go so callbacks can send messages
	program *tea.Program
}

// SetBackend wires the backend components into the TUI model.
func (m *VibeModel) SetBackend(b *Backend) {
	m.backend = b
}

// SetProgram stores the tea.Program reference so agent loop callbacks
// can send messages back into the bubbletea event loop.
func (m *VibeModel) SetProgram(p *tea.Program) {
	m.program = p
}

// ─── bubbletea interface ──────────────────────────────────────────────────────

// Init implements bubbletea.Model.
func (m VibeModel) Init() tea.Cmd { return nil }

// Update implements bubbletea.Model.
func (m VibeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case TokenMsg:
		// Append token to the last assistant line (streaming)
		m.appendToken(msg.Token)
		// Update context usage in status bar
		m.statusBar.ContextPct = m.session.ContextUsagePercent()
		return m, nil

	case ToolStatusMsg:
		m.appendLine(fmt.Sprintf("  ⟳ %s: %s", msg.Tool, msg.Action), m.theme.Dim)
		return m, nil

	case DiffReadyMsg:
		m.diffPreview = &DiffPreviewModel{Diff: msg.Diff, Visible: true}
		return m, nil

	case ApprovalRequestMsg:
		m.approvalGate = &ApprovalGateModel{
			Kind:        msg.Kind,
			Description: msg.Description,
			Visible:     true,
		}
		return m, nil

	case IndexProgressMsg:
		// Could show indexing progress in status bar — for now just ignore
		return m, nil

	case ErrorMsg:
		m.appendLine("✗ "+msg.Err.Error(), m.theme.Error)
		return m, nil

	case StaleFileMsg:
		m.appendLine("⚠ File changed on disk: "+msg.FilePath, m.theme.Dim)
		return m, nil

	case WarnMsg:
		m.appendLine("⚠ "+msg.Text, m.theme.Yellow)
		return m, nil

	case AgentDoneMsg:
		// Agent loop finished — re-enable input
		m.mode = UIModeSession
		m.statusBar.Running = false
		if msg.Err != nil {
			m.appendLine("✗ "+msg.Err.Error(), m.theme.Error)
		}
		// Start a new assistant line for the next response
		m.appendLine("", m.theme.Dim) // blank separator
		return m, nil
	}

	return m, nil
}

// View implements bubbletea.Model.
func (m VibeModel) View() string {
	switch m.mode {
	case UIModeWelcome:
		return RenderWelcomeWithInfo(m.width, m.theme, m.welcomeInfo)
	case UIModeSlashMenu:
		return m.renderSession() + "\n" + m.slashMenu.Render(m.width, m.theme)
	default:
		return m.renderSession()
	}
}

// ─── Constructor ──────────────────────────────────────────────────────────────

// NewVibeModel creates a new VibeModel with defaults.
func NewVibeModel(session *vibecoder.Session, theme Theme) VibeModel {
	return NewVibeModelWithInfo(session, theme, WelcomeInfo{
		Tier:      "Free",
		Model:     "mistralai/mistral-7b-instruct",
		Workspace: session.WorkspaceRoot,
	})
}

// NewVibeModelWithInfo creates a new VibeModel with user info for the welcome screen.
func NewVibeModelWithInfo(session *vibecoder.Session, theme Theme, info WelcomeInfo) VibeModel {
	m := VibeModel{
		session:      session,
		mode:         UIModeWelcome,
		inputHistory: []string{},
		historyIdx:   -1,
		theme:        theme,
		welcomeInfo:  info,
		statusBar: StatusBarState{
			InteractMode:  string(session.InteractMode),
			EditMode:      string(session.EditMode),
			EffortLevel:   string(session.EffortLevel),
			Model:         info.Model,
			PermIndicator: vibecoder.PermissionIndicator(session.EditMode),
		},
	}
	return m
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (m *VibeModel) appendToken(token string) {
	if len(m.chatLines) == 0 {
		m.chatLines = append(m.chatLines, RenderedLine{Content: token, Style: m.theme.Cyan})
		return
	}
	last := &m.chatLines[len(m.chatLines)-1]
	last.Content += token
}

func (m *VibeModel) appendLine(content string, style lipgloss.Style) {
	m.chatLines = append(m.chatLines, RenderedLine{Content: content, Style: style})
}

// startAssistantLine adds a new empty line for the assistant to stream into.
func (m *VibeModel) startAssistantLine() {
	m.appendLine("◆ Neural: ", m.theme.Purple)
}
