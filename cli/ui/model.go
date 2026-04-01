package ui

import (
	"cybermind-cli/api"
	"cybermind-cli/storage"
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

// ChatEntry stores one exchange in the session
type ChatEntry struct {
	Prompt   string
	Response string
}

type Model struct {
	input        textinput.Model
	spinner      spinner.Model
	state        state
	fullResponse string
	displayed    string
	typingIndex  int
	errMsg       string
	lastPrompt   string
	history      []ChatEntry // in-session chat history
	scrollOffset int         // how many lines scrolled up
	width        int
	height       int
}

func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Ask a cybersecurity question..."
	ti.CharLimit = 6000
	ti.Width = 80

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = LabelStyle

	return Model{
		input:   ti,
		spinner: sp,
		state:   stateWaking,
		width:   100,
		height:  30,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, wakeBackend())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		inputWidth := m.width - 8
		if inputWidth < 40 {
			inputWidth = 40
		}
		m.input.Width = inputWidth
		return m, nil

	case wakeMsg:
		if !msg.ok {
			m.errMsg = "Cannot reach backend. Check your internet and try again."
		}
		m.state = stateInput
		m.input.Focus()
		return m, textinput.Blink

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		// Scroll up/down through response with arrow keys or PgUp/PgDn
		if m.state == stateInput || m.state == stateTyping {
			switch msg.Type {
			case tea.KeyPgUp:
				m.scrollOffset += 5
				return m, nil
			case tea.KeyPgDown:
				if m.scrollOffset > 0 {
					m.scrollOffset -= 5
					if m.scrollOffset < 0 {
						m.scrollOffset = 0
					}
				}
				return m, nil
			case tea.KeyUp:
				m.scrollOffset++
				return m, nil
			case tea.KeyDown:
				if m.scrollOffset > 0 {
					m.scrollOffset--
				}
				return m, nil
			}
		}

		if m.state == stateInput {
			if msg.Type == tea.KeyEnter {
				prompt := m.input.Value()
				if prompt == "" {
					return m, nil
				}
				m.state = stateLoading
				m.errMsg = ""
				m.displayed = ""
				m.fullResponse = ""
				m.lastPrompt = prompt
				m.scrollOffset = 0
				m.input.SetValue("")
				return m, tea.Batch(m.spinner.Tick, fetchResponse(prompt))
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
			// Adaptive speed: faster for longer responses
			step := 2
			if len(runes) > 1000 {
				step = 8
			} else if len(runes) > 500 {
				step = 4
			}
			end := m.typingIndex + step
			if end > len(runes) {
				end = len(runes)
			}
			m.displayed += string(runes[m.typingIndex:end])
			m.typingIndex = end
			return m, typeTickCmd()
		}
		// Typing done — save to history
		_ = storage.AddEntry(m.lastPrompt, m.fullResponse)
		m.history = append(m.history, ChatEntry{
			Prompt:   m.lastPrompt,
			Response: m.fullResponse,
		})
		// Clear displayed so it doesn't show twice alongside history
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

func fetchResponse(prompt string) tea.Cmd {
	return func() tea.Msg {
		resp, err := api.SendPrompt(prompt)
		return apiResponseMsg{response: resp, err: err}
	}
}

func typeTickCmd() tea.Cmd {
	return tea.Tick(6*time.Millisecond, func(t time.Time) tea.Msg {
		return typeTickMsg{}
	})
}
