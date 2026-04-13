package tui

import (
	"context"
	"strings"
	"time"

	"cybermind-cli/vibecoder"

	tea "github.com/charmbracelet/bubbletea"
)

// ─── Key handler ──────────────────────────────────────────────────────────────

func (m VibeModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Any key on welcome screen transitions to session
	if m.mode == UIModeWelcome {
		m.mode = UIModeSession
		return m, nil
	}

	// While agent is running: only allow Ctrl+C to cancel
	if m.mode == UIModeRunning {
		if msg.Type == tea.KeyCtrlC {
			m.cancelAgentLoop()
			m.mode = UIModeSession
			m.statusBar.Running = false
			m.appendLine("⊘ Cancelled", m.theme.Yellow)
		}
		return m, nil
	}

	// Approval gate: handle A/S/E keys
	if m.approvalGate != nil && m.approvalGate.Visible {
		switch msg.String() {
		case "a", "A":
			m.approvalGate.Visible = false
			m.appendLine("✓ Approved", m.theme.Green)
			return m, nil
		case "s", "S":
			m.approvalGate.Visible = false
			m.appendLine("⊘ Skipped", m.theme.Dim)
			return m, nil
		case "e", "E":
			m.approvalGate.Visible = false
			m.appendLine("✎ Edit manually", m.theme.Dim)
			return m, nil
		}
	}

	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyCtrlD:
		return m, tea.Quit

	case tea.KeyUp:
		if m.mode == UIModeSlashMenu {
			m.slashMenu.MoveUp()
		} else {
			m.navigateHistory(-1)
		}
		return m, nil

	case tea.KeyDown:
		if m.mode == UIModeSlashMenu {
			m.slashMenu.MoveDown()
		} else {
			m.navigateHistory(1)
		}
		return m, nil

	case tea.KeyTab:
		m.cycleEditMode(1)
		return m, nil

	case tea.KeyShiftTab:
		m.cycleEditMode(-1)
		return m, nil

	case tea.KeyEnter:
		if m.mode == UIModeSlashMenu {
			if sel := m.slashMenu.Selected(); sel != "" {
				m.inputBuf = sel
				m.mode = UIModeSession
				return m.submitInput()
			}
		}
		return m.submitInput()

	case tea.KeyBackspace:
		if len(m.inputBuf) > 0 {
			m.inputBuf = m.inputBuf[:len(m.inputBuf)-1]
			if m.mode == UIModeSlashMenu {
				if len(m.inputBuf) == 0 {
					m.mode = UIModeSession
				} else if strings.HasPrefix(m.inputBuf, "/") {
					m.slashMenu.Filter(m.inputBuf[1:])
				} else {
					m.mode = UIModeSession
				}
			}
		}
		return m, nil

	case tea.KeyRunes:
		m.inputBuf += msg.String()
		if m.inputBuf == "/" {
			m.mode = UIModeSlashMenu
			m.slashMenu = NewSlashMenuModel()
		} else if m.mode == UIModeSlashMenu {
			m.slashMenu.Filter(m.inputBuf[1:])
		}
		return m, nil

	case tea.KeyEsc:
		if m.mode == UIModeSlashMenu {
			m.mode = UIModeSession
		}
		return m, nil
	}

	return m, nil
}

// ─── Input submission ─────────────────────────────────────────────────────────

func (m VibeModel) submitInput() (tea.Model, tea.Cmd) {
	if m.inputBuf == "" {
		return m, nil
	}

	// Slash commands
	if strings.HasPrefix(m.inputBuf, "/") {
		return m.handleSlashCommand(m.inputBuf)
	}

	prompt := strings.TrimSpace(m.inputBuf)
	m.inputHistory = append(m.inputHistory, prompt)
	m.historyIdx = -1
	m.inputBuf = ""
	m.mode = UIModeSession

	// Display user message
	m.appendLine("▶ You: "+prompt, m.theme.User)

	// If no backend wired, try direct chat via main API as fallback
	if m.backend == nil || m.backend.AgentLoop == nil {
		m.mode = UIModeRunning
		m.statusBar.Running = true
		m.startAssistantLine()
		return m, m.runDirectChatCmd(prompt)
	}

	// Add user message to session history
	m.session.History = append(m.session.History, vibecoder.Message{
		Role:      vibecoder.RoleUser,
		Content:   prompt,
		Timestamp: time.Now(),
		Tokens:    vibecoder.EstimateTokensPublic(prompt),
	})

	// Start the agent loop in a goroutine, send results back via tea.Program.Send
	m.mode = UIModeRunning
	m.statusBar.Running = true
	m.startAssistantLine()

	return m, m.runAgentLoopCmd(prompt)
}

// runAgentLoopCmd returns a tea.Cmd that runs the agent loop in a goroutine
// and sends messages back to the TUI via the program reference.
func (m VibeModel) runAgentLoopCmd(prompt string) tea.Cmd {
	if m.program == nil || m.backend == nil || m.backend.AgentLoop == nil {
		return nil
	}

	prog := m.program
	loop := m.backend.AgentLoop

	// Wire callbacks to send messages into the bubbletea event loop
	loop.SetOnToken(func(token string) {
		prog.Send(TokenMsg{Token: token})
	})
	loop.SetOnToolStatus(func(tool, action string) {
		prog.Send(ToolStatusMsg{Tool: tool, Action: action})
	})
	loop.SetOnWarn(func(msg string) {
		prog.Send(WarnMsg{Text: msg})
	})

	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		// Store cancel so Ctrl+C can stop it
		if m.backend != nil {
			m.backend.cancelLoop = cancel
		}
		defer cancel()

		err := loop.Run(ctx)
		return AgentDoneMsg{Err: err}
	}
}

// cancelAgentLoop cancels the running agent loop goroutine.
func (m *VibeModel) cancelAgentLoop() {
	if m.backend != nil && m.backend.cancelLoop != nil {
		m.backend.cancelLoop()
		m.backend.cancelLoop = nil
	}
}

// runDirectChatCmd is a fallback when the full backend isn't wired.
// It calls the main CyberMind /chat endpoint directly (same as cybermind chat).
func (m VibeModel) runDirectChatCmd(prompt string) tea.Cmd {
	if m.program == nil {
		return nil
	}
	prog := m.program

	// Build history from session
	history := make([]vibecoder.APIMessage, 0, len(m.session.History))
	for _, msg := range m.session.History {
		if msg.Role == vibecoder.RoleUser || msg.Role == vibecoder.RoleAssistant {
			history = append(history, vibecoder.APIMessage{
				Role:    string(msg.Role),
				Content: msg.Content,
			})
		}
	}

	return func() tea.Msg {
		_, err := vibecoder.SendVibeChat(prompt, history, func(token string) {
			prog.Send(TokenMsg{Token: token})
		})
		return AgentDoneMsg{Err: err}
	}
}

// ─── Slash command handler ────────────────────────────────────────────────────

func (m VibeModel) handleSlashCommand(cmd string) (tea.Model, tea.Cmd) {
	m.mode = UIModeSession
	trimmed := strings.TrimSpace(cmd)

	switch trimmed {
	case "/exit":
		return m, tea.Quit

	case "/clear":
		m.chatLines = nil
		m.session.History = nil
		m.session.TokensUsed = 0
		m.appendLine("✓ Context cleared", m.theme.Green)

	case "/compress":
		if m.backend != nil && m.backend.Memory != nil {
			vibecoder.CompressContext(m.session, m.backend.Memory)
			m.appendLine("✓ Context compressed", m.theme.Green)
		}

	case "/undo":
		if snap, ok := m.session.PopUndo(); ok {
			m.appendLine("↩ Undoing: "+snap.Path, m.theme.Yellow)
		} else {
			m.appendLine("Nothing to undo", m.theme.Dim)
		}

	case "/mode agent":
		m.session.SwitchMode(vibecoder.InteractModeAgent)
		m.statusBar.InteractMode = "agent"
		m.appendLine("⇄ Switched to Agent mode", m.theme.Cyan)

	case "/mode chat":
		m.session.SwitchMode(vibecoder.InteractModeChat)
		m.statusBar.InteractMode = "chat"
		m.appendLine("⇄ Switched to Chat mode", m.theme.Cyan)

	case "/effort low":
		m.session.SetEffortLevel(vibecoder.EffortLow)
		m.statusBar.EffortLevel = "low"
		m.appendLine("⇄ Effort: low", m.theme.Dim)

	case "/effort medium":
		m.session.SetEffortLevel(vibecoder.EffortMedium)
		m.statusBar.EffortLevel = "medium"
		m.appendLine("⇄ Effort: medium", m.theme.Dim)

	case "/effort max":
		m.session.SetEffortLevel(vibecoder.EffortMax)
		m.statusBar.EffortLevel = "max"
		m.appendLine("⇄ Effort: max", m.theme.Cyan)

	case "/debug":
		m.session.ActivateDebugMode()
		m.appendLine("🔍 Debug mode activated", m.theme.Yellow)

	case "/help":
		m.appendLine("Commands: /clear /compress /undo /mode /effort /debug /exit /add <file>", m.theme.Dim)

	default:
		if strings.HasPrefix(trimmed, "/add ") {
			path := strings.TrimPrefix(trimmed, "/add ")
			m.appendLine("📎 Added to context: "+path, m.theme.Green)
		} else if strings.HasPrefix(trimmed, "/model ") {
			model := strings.TrimPrefix(trimmed, "/model ")
			m.statusBar.Model = model
			m.appendLine("⇄ Model override: "+model, m.theme.Cyan)
		} else {
			m.appendLine("Unknown command: "+trimmed+" (type /help)", m.theme.Dim)
		}
	}

	m.inputBuf = ""
	return m, nil
}

// ─── Edit mode cycling ────────────────────────────────────────────────────────

func (m *VibeModel) cycleEditMode(dir int) {
	modes := []vibecoder.EditMode{
		vibecoder.EditModeGuard,
		vibecoder.EditModeAutoEdit,
		vibecoder.EditModeBlueprint,
		vibecoder.EditModeAutopilot,
		vibecoder.EditModeUnleashed,
	}
	current := m.session.EditMode
	idx := 0
	for i, mode := range modes {
		if mode == current {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(modes)) % len(modes)
	m.session.EditMode = modes[idx]
	m.statusBar.EditMode = string(modes[idx])
	m.statusBar.PermIndicator = vibecoder.PermissionIndicator(modes[idx])
	m.appendLine("⇄ Edit mode: "+string(modes[idx]), m.theme.Dim)
}

// ─── Input history navigation ─────────────────────────────────────────────────

func (m *VibeModel) navigateHistory(dir int) {
	if len(m.inputHistory) == 0 {
		return
	}
	m.historyIdx += dir
	if m.historyIdx < 0 {
		m.historyIdx = 0
	}
	if m.historyIdx >= len(m.inputHistory) {
		m.historyIdx = len(m.inputHistory) - 1
		m.inputBuf = ""
		return
	}
	m.inputBuf = m.inputHistory[len(m.inputHistory)-1-m.historyIdx]
}
