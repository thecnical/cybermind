package ui

import (
	"cybermind-cli/api"
	"cybermind-cli/storage"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type state int

const (
	stateWaking  state = iota
	stateInput   state = iota
	stateLoading state = iota
	stateTyping  state = iota
)

// maxContextMessages — keep last 20 messages (10 exchanges) in context
const maxContextMessages = 20

type apiResponseMsg struct {
	response string
	err      error
}

type typeTickMsg struct{}
type wakeMsg struct{ ok bool }

type ChatEntry struct {
	Prompt   string
	Response string
}

type Model struct {
	input           textinput.Model
	spinner         spinner.Model
	state           state
	fullResponse    string
	displayed       string
	typingIndex     int
	errMsg          string
	lastPrompt      string
	history         []ChatEntry
	contextMessages []api.Message
	scrollOffset    int
	width           int
	height          int
	localIP         string // passed in from main
	lastUsage       string // "plan:free  today:3/20"
}

func NewModel(localIP string) Model {
	ti := textinput.New()
	ti.Placeholder = "Ask anything about cybersecurity..."
	ti.CharLimit = 6000
	ti.Width = 60
	ti.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = LabelStyle

	// BUG FIX: storage.Load() must be called BEFORE NewModel in main.go
	// Load last 5 exchanges as initial context
	contextMsgs := loadHistoryAsContext(5)

	return Model{
		input:           ti,
		spinner:         sp,
		state:           stateWaking,
		width:           80,
		height:          24,
		contextMessages: contextMsgs,
		localIP:         localIP,
	}
}

func loadHistoryAsContext(n int) []api.Message {
	entries := storage.GetHistory()
	if len(entries) == 0 {
		return []api.Message{}
	}
	start := len(entries) - n
	if start < 0 {
		start = 0
	}
	recent := entries[start:]
	var msgs []api.Message
	for _, e := range recent {
		msgs = append(msgs, api.Message{Role: "user", Content: e.User})
		msgs = append(msgs, api.Message{Role: "assistant", Content: e.AI})
	}
	return msgs
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, wakeBackend())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		w := m.width - 10
		if w < 30 {
			w = 30
		}
		m.input.Width = w
		return m, nil

	case wakeMsg:
		if !msg.ok {
			// Backend is sleeping (Render cold start) — don't show error.
			// The keepalive on the backend prevents this after first deploy,
			// but on first cold start it can take 30-60s.
			// User can still type — post() will auto-wait and retry.
			m.errMsg = "⟳ Backend waking up — your message will send automatically once connected"
		}
		m.state = stateInput
		m.input.Focus()
		return m, textinput.Blink

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		// Ctrl+L — clear chat screen
		if msg.Type == tea.KeyCtrlL {
			m.history = []ChatEntry{}
			m.displayed = ""
			m.fullResponse = ""
			m.errMsg = ""
			m.scrollOffset = 0
			return m, nil
		}

		if m.state != stateLoading && m.state != stateWaking {
			switch msg.Type {
			case tea.KeyPgUp:
				m.scrollOffset += 10
				return m, nil
			case tea.KeyPgDown:
				if m.scrollOffset >= 10 {
					m.scrollOffset -= 10
				} else {
					m.scrollOffset = 0
				}
				return m, nil
			}
		}

		if m.state == stateInput {
			if msg.Type == tea.KeyEnter {
				prompt := m.input.Value()
				if strings.TrimSpace(prompt) == "" {
					return m, nil
				}
				m.state = stateLoading
				m.errMsg = ""
				m.displayed = ""
				m.fullResponse = ""
				m.lastPrompt = prompt
				m.scrollOffset = 0
				m.input.SetValue("")
				return m, tea.Batch(m.spinner.Tick, fetchWithContext(prompt, m.contextMessages))
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}

	case apiResponseMsg:
		if msg.err != nil {
			m.state = stateInput
			errStr := msg.err.Error()
			// Upgrade required — legacy user without API key
			if strings.HasPrefix(errStr, "UPGRADE_REQUIRED:") {
				parts := strings.SplitN(strings.TrimPrefix(errStr, "UPGRADE_REQUIRED:"), "|", 2)
				m.errMsg = "⚠  " + parts[0]
				if len(parts) > 1 {
					m.errMsg += "\n  " + parts[1]
				}
				m.errMsg += "\n  Get your free key: https://cybermind.thecnical.dev"
			} else if strings.Contains(errStr, "API key required") ||
				strings.Contains(errStr, "api key required") ||
				strings.Contains(errStr, "Authorization required") {
				m.errMsg = "No API key set. Run: cybermind --key cp_live_xxxxx\n  Get yours free at: https://cybermind.thecnical.dev/dashboard"
			} else if strings.Contains(errStr, "Invalid API key") ||
				strings.Contains(errStr, "invalid api key") {
				m.errMsg = "Invalid API key. Run: cybermind --key cp_live_xxxxx\n  Get a new key at: https://cybermind.thecnical.dev/dashboard"
			} else if strings.Contains(errStr, "starting up") || strings.Contains(errStr, "cold start") {
				m.errMsg = "⟳ Backend is starting up (30-60s). Please resend once connected"
			} else if strings.Contains(errStr, "cannot connect") || strings.Contains(errStr, "backend_down") {
				m.errMsg = "⟳ Connecting to backend... please resend your message"
			} else {
				m.errMsg = errStr
			}
			m.input.Focus()
			return m, textinput.Blink
		}
		m.fullResponse = msg.response
		m.typingIndex = 0
		m.displayed = ""
		m.state = stateTyping
		m.scrollOffset = 0 // BUG FIX: reset scroll on new response
		return m, typeTickCmd()

	case typeTickMsg:
		runes := []rune(m.fullResponse)
		if m.typingIndex < len(runes) {
			step := 3
			if len(runes) > 2000 {
				step = 20
			} else if len(runes) > 800 {
				step = 10
			} else if len(runes) > 300 {
				step = 5
			}
			end := m.typingIndex + step
			if end > len(runes) {
				end = len(runes)
			}
			m.displayed += string(runes[m.typingIndex:end])
			m.typingIndex = end
			return m, typeTickCmd()
		}

		_ = storage.AddEntry(m.lastPrompt, m.fullResponse)
		m.history = append(m.history, ChatEntry{
			Prompt:   m.lastPrompt,
			Response: m.fullResponse,
		})

		// Fetch and update usage in background
		go func() {
			if key := api.GetAPIKey(); key != "" {
				plan, today, limit, err := api.FetchUsage(key)
				if err == nil {
					m.lastUsage = fmt.Sprintf("plan:%s  today:%d/%s", plan, today, func() string {
						if limit < 0 {
							return "∞"
						}
						return fmt.Sprintf("%d", limit)
					}())
				}
			}
		}()

		// BUG FIX: proper context trimming — circular buffer
		m.contextMessages = append(m.contextMessages,
			api.Message{Role: "user", Content: m.lastPrompt},
			api.Message{Role: "assistant", Content: m.fullResponse},
		)
		if len(m.contextMessages) > maxContextMessages {
			// Keep only the last maxContextMessages
			m.contextMessages = m.contextMessages[len(m.contextMessages)-maxContextMessages:]
		}

		m.displayed = ""
		m.fullResponse = ""
		m.state = stateInput
		m.input.Focus()
		return m, textinput.Blink

	case spinner.TickMsg:
		if m.state == stateLoading || m.state == stateWaking {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func wakeBackend() tea.Cmd {
	return func() tea.Msg {
		ok := api.WakeUp()
		return wakeMsg{ok: ok}
	}
}

func fetchWithContext(prompt string, history []api.Message) tea.Cmd {
	return func() tea.Msg {
		resp, err := api.SendChat(prompt, history)
		return apiResponseMsg{response: resp, err: err}
	}
}

func typeTickCmd() tea.Cmd {
	return tea.Tick(5*time.Millisecond, func(t time.Time) tea.Msg {
		return typeTickMsg{}
	})
}
