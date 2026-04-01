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
	stateInput   state = iota
	stateLoading state = iota
	stateTyping  state = iota
)

type apiResponseMsg struct {
	response string
	err      error
}

type typeTickMsg struct{}

type Model struct {
	input        textinput.Model
	spinner      spinner.Model
	state        state
	fullResponse string
	displayed    string
	typingIndex  int
	errMsg       string
	lastPrompt   string
	width        int
}

func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Type your cybersecurity query..."
	ti.CharLimit = 500
	ti.Width = 70
	ti.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = LabelStyle

	return Model{
		input:   ti,
		spinner: sp,
		state:   stateInput,
	}
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
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
		return m, typeTickCmd()

	case typeTickMsg:
		runes := []rune(m.fullResponse)
		if m.typingIndex < len(runes) {
			m.displayed += string(runes[m.typingIndex])
			m.typingIndex++
			return m, typeTickCmd()
		}
		// Typing done — save to history
		_ = storage.AddEntry(m.lastPrompt, m.fullResponse)
		m.state = stateInput
		m.input.Focus()
		return m, textinput.Blink

	case spinner.TickMsg:
		if m.state == stateLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func fetchResponse(prompt string) tea.Cmd {
	return func() tea.Msg {
		resp, err := api.SendPrompt(prompt)
		return apiResponseMsg{response: resp, err: err}
	}
}

func typeTickCmd() tea.Cmd {
	return tea.Tick(12*time.Millisecond, func(t time.Time) tea.Msg {
		return typeTickMsg{}
	})
}
