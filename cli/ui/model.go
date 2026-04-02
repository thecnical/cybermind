package ui

import (
	"cybermind-cli/api"
	"cybermind-cli/storage"
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

type apiResponseMsg struct {
	response string
	err      error
}

type typeTickMsg struct{}
type wakeMsg struct{ ok bool }

// ChatEntry for display in UI
type ChatEntry struct {
	Prompt   string
	Response string
}

// Max messages to keep in memory context (last N exchanges = 2*N messages)
const maxContextMessages = 20

type Model struct {
	input           textinput.Model
	spinner         spinner.Model
	state           state
	fullResponse    string
	displayed       string
	typingIndex     int
	errMsg          string
	lastPrompt      string
	history         []ChatEntry    // UI display history
	contextMessages []api.Message  // conversation memory sent to backend
	scrollOffset    int
	width           int
	height          int
}

func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Ask anything about cybersecurity..."
	ti.CharLimit = 6000
	ti.Width = 60
	ti.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = LabelStyle

	// Phase C: Load last 5 exchanges from local history as initial context
	contextMsgs := loadHistoryAsContext(5)

	return Model{
		input:           ti,
		spinner:         sp,
		state:           stateWaking,
		width:           80,
		height:          24,
		contextMessages: contextMsgs,
	}
}

// loadHistoryAsContext reads local history and converts last N entries to messages
func loadHistoryAsContext(n int) []api.Message {
	entries := storage.GetHistory()
	if len(entries) == 0 {
		return []api.Message{}
	}

	// Take last N entries
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
			m.errMsg = "Cannot reach backend — check internet connection"
		}
		m.state = stateInput
		m.input.Focus()
		return m, textinput.Blink

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
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
				// Send with full conversation context
				return m, tea.Batch(m.spinner.Tick, fetchWithContext(prompt, m.contextMessages))
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}

	case apiResponseMsg:
		if msg.err != nil {
			m.state = stateInput
			m.errMsg = msg.err.Error()
			m.input.Focus()
			return m, textinput.Blink
		}
		m.fullResponse = msg.response
		m.typingIndex = 0
		m.displayed = ""
		m.state = stateTyping
		m.scrollOffset = 0
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

		// Typing done — save to local history
		_ = storage.AddEntry(m.lastPrompt, m.fullResponse)

		// Add to UI display history
		m.history = append(m.history, ChatEntry{
			Prompt:   m.lastPrompt,
			Response: m.fullResponse,
		})

		// Add to conversation context for next request
		m.contextMessages = append(m.contextMessages,
			api.Message{Role: "user", Content: m.lastPrompt},
			api.Message{Role: "assistant", Content: m.fullResponse},
		)
		// Keep context within limit
		if len(m.contextMessages) > maxContextMessages {
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

// fetchWithContext sends prompt with full conversation history
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
