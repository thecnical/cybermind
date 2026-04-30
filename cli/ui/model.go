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
	stateWaking    state = iota
	stateInput     state = iota
	stateLoading   state = iota
	stateTyping    state = iota
	stateKeyPrompt state = iota // inline API key entry
)

// maxContextMessages — keep last 20 messages (10 exchanges) in context
const maxContextMessages = 20

type apiResponseMsg struct {
	response string
	err      error
}

// streamTokenMsg carries a single streamed token from the AI
type streamTokenMsg struct {
	token string
	done  bool
	err   error
}

type typeTickMsg struct{}
type wakeMsg struct{ ok bool }
type keySavedMsg struct{ key string }

type ChatEntry struct {
	Prompt   string
	Response string
}

type Model struct {
	input           textinput.Model
	keyInput        textinput.Model // separate input for API key entry
	spinner         spinner.Model
	state           state
	fullResponse    string
	displayed       string
	typingIndex     int
	errMsg          string
	infoMsg         string // green info message (e.g. key saved)
	lastPrompt      string
	history         []ChatEntry
	contextMessages []api.Message
	scrollOffset    int
	width           int
	height          int
	localIP         string
	lastUsage       string
}

func NewModel(localIP string) Model {
	ti := textinput.New()
	ti.Placeholder = "Ask anything about cybersecurity..."
	ti.CharLimit = 6000
	ti.Width = 60
	ti.Focus()

	ki := textinput.New()
	ki.Placeholder = "Paste your API key (cp_live_xxxxx)..."
	ki.CharLimit = 128
	ki.Width = 60
	ki.EchoMode = textinput.EchoPassword // mask the key while typing
	ki.EchoCharacter = '•'

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = LabelStyle

	contextMsgs := loadHistoryAsContext(5)

	// Start in key prompt mode ONLY if no key is set
	// If key is saved, always start in waking state (connect to backend)
	initialState := stateWaking
	if api.GetAPIKey() == "" {
		initialState = stateKeyPrompt
		ti.Blur()
		ki.Focus()
	}

	return Model{
		input:           ti,
		keyInput:        ki,
		spinner:         sp,
		state:           initialState,
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
	// If no key set, start in key prompt — don't wake backend yet
	if m.state == stateKeyPrompt {
		return textinput.Blink
	}
	return tea.Batch(m.spinner.Tick, wakeBackend())
}

func isAPIKeyError(errStr string) bool {
	// Only trigger key prompt for EXPLICIT key errors from backend
	// NOT for network errors, cold starts, or generic errors
	// This prevents the key prompt from showing when key IS saved but backend is slow
	lower := strings.ToLower(errStr)
	
	// Must be an explicit auth error — not just any error
	explicitAuthErrors := []string{
		"api key required",
		"authorization required",
		"invalid api key",
		"invalid or revoked",
		"revoked api key",
		"no api key",
		"missing api key",
		"unauthorized: key",
	}
	for _, e := range explicitAuthErrors {
		if strings.Contains(lower, e) {
			// Double-check: if we have a key saved, don't show key prompt
			// (backend might be returning stale error)
			if api.GetAPIKey() != "" {
				return false // key is saved — don't ask again
			}
			return true
		}
	}
	
	// "key is required" only if no key is saved
	if strings.Contains(lower, "key is required") {
		return api.GetAPIKey() == ""
	}
	
	return false
}

func isEmailNotVerifiedError(errStr string) bool {
	return strings.Contains(errStr, "Email not verified") ||
		strings.Contains(errStr, "email not verified") ||
		strings.Contains(errStr, "EMAIL_NOT_VERIFIED") ||
		strings.Contains(errStr, "verify your email") ||
		strings.Contains(errStr, "Check your inbox")
}

func isDailyLimitError(errStr string) bool {
	return strings.Contains(errStr, "Daily limit") ||
		strings.Contains(errStr, "daily limit") ||
		strings.Contains(errStr, "Monthly limit") ||
		strings.Contains(errStr, "Request limit") ||
		strings.Contains(errStr, "limit reached")
}

func isOSMismatchError(errStr string) bool {
	return strings.Contains(errStr, "OS_MISMATCH") ||
		strings.Contains(errStr, "was created for") ||
		strings.Contains(errStr, "cross-platform")
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
		m.keyInput.Width = w
		return m, nil

	case wakeMsg:
		// Backend check done — go to input regardless
		m.state = stateInput
		m.input.Focus()
		if !msg.ok {
			m.infoMsg = "Backend may be starting up — your first message will auto-wake it"
		} else if len(m.history) == 0 && m.infoMsg == "" {
			// Read cached user name immediately — no network call needed
			name := api.GetCachedUserName()
			if name != "" {
				m.infoMsg = fmt.Sprintf("Hey %s! Ready. Ask anything.", name)
			} else {
				m.infoMsg = "Ready. Ask anything about cybersecurity."
			}
		}
		return m, textinput.Blink

	case keySavedMsg:
		// Parse user name from plan info if present
		userName := ""
		planStr := msg.key // reuse key field to pass plan info
		if idx := strings.Index(planStr, "|NAME|"); idx >= 0 {
			rest := planStr[idx+6:]
			if endIdx := strings.Index(rest, "|"); endIdx >= 0 {
				userName = rest[:endIdx]
			} else {
				userName = rest
			}
		}

		if userName != "" {
			m.infoMsg = fmt.Sprintf("✓ Welcome, %s! Connecting to CyberMind...", userName)
		} else {
			m.infoMsg = "✓ Key saved! Connecting to CyberMind..."
		}
		m.errMsg = ""
		m.state = stateWaking
		m.keyInput.SetValue("")
		m.input.SetValue("")
		// Now wake the backend
		return m, tea.Batch(m.spinner.Tick, wakeBackend())

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		// ── Key prompt mode ───────────────────────────────────────────────
		if m.state == stateKeyPrompt {
			switch msg.Type {
			case tea.KeyEscape:
				// Cancel key entry — go back to input
				m.state = stateInput
				m.keyInput.SetValue("")
				m.errMsg = "Key entry cancelled. Type: cybermind --key cp_live_xxxxx to set your key."
				m.input.Focus()
				return m, textinput.Blink

			case tea.KeyEnter:
				key := strings.TrimSpace(m.keyInput.Value())
				if key == "" {
					m.errMsg = "No key entered. Press Esc to cancel."
					return m, nil
				}
				if !strings.HasPrefix(key, "cp_live_") && !strings.HasPrefix(key, "sk_live_cm_") {
					m.errMsg = "Invalid key format — must start with cp_live_"
					m.keyInput.SetValue("")
					return m, textinput.Blink
				}
				if len(key) < 16 {
					m.errMsg = "Key too short — check your dashboard."
					m.keyInput.SetValue("")
					return m, textinput.Blink
				}
				// Save key and return to chat
				return m, saveKeyCmd(key)

			default:
				var cmd tea.Cmd
				m.keyInput, cmd = m.keyInput.Update(msg)
				return m, cmd
			}
		}

		// Ctrl+L — clear chat screen
		if msg.Type == tea.KeyCtrlL {
			m.history = []ChatEntry{}
			m.displayed = ""
			m.fullResponse = ""
			m.errMsg = ""
			m.infoMsg = ""
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
				m.infoMsg = ""
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

			if strings.HasPrefix(errStr, "UPGRADE_REQUIRED:") {
				parts := strings.SplitN(strings.TrimPrefix(errStr, "UPGRADE_REQUIRED:"), "|", 2)
				m.errMsg = "⚠  " + parts[0]
				if len(parts) > 1 {
					m.errMsg += " | " + parts[1]
				}
				m.errMsg += " → https://cybermindcli1.vercel.app/plans"
			} else if isEmailNotVerifiedError(errStr) {
				// Email not verified — show clear message, don't ask for key again
				m.errMsg = "✉  Email not verified. Check your inbox and click the verification link.\n  Then try again. Resend at: https://cybermindcli1.vercel.app/dashboard"
				m.state = stateInput
				m.input.Focus()
			} else if isDailyLimitError(errStr) {
				m.errMsg = "⚠  " + errStr + "\n  Upgrade at: https://cybermindcli1.vercel.app/plans"
				m.state = stateInput
				m.input.Focus()
			} else if isAPIKeyError(errStr) {
				// Switch to inline key prompt mode
				m.state = stateKeyPrompt
				m.errMsg = ""
				m.infoMsg = ""
				m.keyInput.SetValue("")
				m.keyInput.Focus()
				return m, textinput.Blink
			} else if isOSMismatchError(errStr) {
				m.errMsg = errStr + "\n  Get a new key at: https://cybermindcli1.vercel.app/dashboard"
			} else if strings.Contains(errStr, "starting up") ||
				strings.Contains(errStr, "cold start") ||
				strings.Contains(errStr, "backend_down") ||
				strings.Contains(errStr, "cannot connect") ||
				strings.Contains(errStr, "took too long") {
				// Backend was sleeping (Render free tier cold start ~30-60s)
				// Auto-retry automatically — user doesn't need to resend
				m.infoMsg = "⟳ Backend waking up — auto-retrying your message..."
				m.errMsg = ""
				m.state = stateLoading
				lastPrompt := m.lastPrompt
				lastContext := m.contextMessages
				return m, tea.Batch(
					m.spinner.Tick,
					retryAfterWake(lastPrompt, lastContext),
				)
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

		_ = storage.AddEntry(m.lastPrompt, m.fullResponse)
		m.history = append(m.history, ChatEntry{
			Prompt:   m.lastPrompt,
			Response: m.fullResponse,
		})

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

		m.contextMessages = append(m.contextMessages,
			api.Message{Role: "user", Content: m.lastPrompt},
			api.Message{Role: "assistant", Content: m.fullResponse},
		)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func wakeBackend() tea.Cmd {
	return func() tea.Msg {
		ok := api.WakeUp()
		return wakeMsg{ok: ok}
	}
}

// retryAfterWake waits for the backend to wake up then retries the prompt.
// Used when the first request fails due to Render cold start.
func retryAfterWake(prompt string, history []api.Message) tea.Cmd {
	return func() tea.Msg {
		// Wait up to 90 seconds for backend to wake
		api.WakeUpWithProgress(90*time.Second, nil)
		// Small buffer after wake
		time.Sleep(1 * time.Second)
		// Retry with full context
		var fullText strings.Builder
		resp, err := api.SendChatStream(prompt, history, func(token string) {
			fullText.WriteString(token)
		})
		if err != nil {
			return apiResponseMsg{err: err}
		}
		if fullText.Len() > 0 {
			return apiResponseMsg{response: fullText.String()}
		}
		return apiResponseMsg{response: resp}
	}
}

func fetchWithContext(prompt string, history []api.Message) tea.Cmd {
	return func() tea.Msg {
		// Try streaming first — falls back to regular if streaming fails
		var fullText strings.Builder
		resp, err := api.SendChatStream(prompt, history, func(token string) {
			fullText.WriteString(token)
		})
		if err != nil {
			return apiResponseMsg{err: err}
		}
		// Use streamed text if available, otherwise use returned value
		result := fullText.String()
		if result == "" {
			result = resp
		}
		return apiResponseMsg{response: result, err: nil}
	}
}

func saveKeyCmd(key string) tea.Cmd {
	return func() tea.Msg {
		if err := api.SaveKey(key); err != nil {
			return apiResponseMsg{err: fmt.Errorf("failed to save key: %v", err)}
		}
		// Validate key and get user name for welcome message
		planInfo, _ := api.ValidateKey(key)
		return keySavedMsg{key: planInfo} // pass planInfo (contains NAME if available)
	}
}

func typeTickCmd() tea.Cmd {
	return tea.Tick(5*time.Millisecond, func(t time.Time) tea.Msg {
		return typeTickMsg{}
	})
}
