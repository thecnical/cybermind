package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const defaultBackendURL = "https://cybermind-backend-8yrt.onrender.com"

func getBaseURL() string {
	if url := os.Getenv("CYBERMIND_API"); url != "" {
		return url
	}
	return defaultBackendURL
}

// getAPIKey returns the API key from env, config file, or empty string
func getAPIKey() string {
	// 1. Environment variable
	if key := os.Getenv("CYBERMIND_KEY"); key != "" {
		return key
	}
	// 2. Config file ~/.cybermind/config.json
	homedir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	configPath := homedir + "/.cybermind/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var cfg struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.Key
}

// httpClient for actual AI requests — long timeout because AI can take 60-180s
var httpClient = &http.Client{Timeout: 200 * time.Second}

// fastClient for health/ping checks — short timeout
var fastClient = &http.Client{Timeout: 8 * time.Second}

// Message for conversation history
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Prompt   string    `json:"prompt"`
	Messages []Message `json:"messages"`
}

type promptResponse struct {
	Success  bool   `json:"success"`
	Response string `json:"response"`
	Analysis string `json:"analysis"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Time     string `json:"time"`
	Error    string `json:"error"`
}

// WakeUp pings /ping to check if backend is alive.
// Returns true immediately if alive, false if unreachable after quick check.
// Does NOT block — the UI shows a soft warning and lets user type anyway.
func WakeUp() bool {
	resp, err := fastClient.Get(getBaseURL() + "/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// waitForBackend blocks until the backend responds or maxWait is exceeded.
// Used internally before sending actual requests.
// Returns nil if backend is up, error if it never came up.
func waitForBackend(maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	// Try every 3 seconds
	for time.Now().Before(deadline) {
		resp, err := fastClient.Get(getBaseURL() + "/ping")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("backend did not respond within %s", maxWait)
}

// post sends a JSON request and returns the AI response string.
// If the backend is sleeping (521/502/non-JSON), it waits up to 90s for it to wake,
// then retries automatically — transparent to the user.
func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	// Try up to 3 times with wake-wait between attempts
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		result, err := doPost(endpoint, payload)
		if err == nil {
			return result, nil
		}
		lastErr = err

		// If it's a backend-down error, wait for it to wake then retry
		if isBackendDown(err) && attempt < 3 {
			// Wait up to 90s for backend to come up
			if waitErr := waitForBackend(90 * time.Second); waitErr != nil {
				// Backend didn't wake — return clear message
				return "", fmt.Errorf("backend is starting up (Render cold start). Please wait 30-60s and try again")
			}
			// Backend is up now — retry immediately
			continue
		}
		// Non-recoverable error — return immediately
		break
	}
	return "", lastErr
}

// doPost performs a single HTTP POST and parses the JSON response.
func doPost(endpoint string, payload []byte) (string, error) {
	req, err := http.NewRequest("POST", getBaseURL()+endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	req.Header.Set("Content-Type", "application/json")
	// Attach API key if available
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Non-JSON response = backend is starting up or Cloudflare error page
	if len(raw) == 0 || raw[0] != '{' {
		return "", fmt.Errorf("_backend_down: status %d — server starting up", resp.StatusCode)
	}

	var result promptResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("_backend_down: malformed response (status %d)", resp.StatusCode)
	}
	if !result.Success {
		if result.Error == "" {
			return "", fmt.Errorf("backend error (status %d)", resp.StatusCode)
		}
		return "", fmt.Errorf("%s", result.Error)
	}
	if result.Analysis != "" {
		return result.Analysis, nil
	}
	return result.Response, nil
}

// isBackendDown returns true if the error indicates the backend is down/starting
func isBackendDown(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) > 13 && msg[:13] == "_backend_down"
}

// GetPublicIP fetches the public IP of the machine
func GetPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}
	return string(body)
}

// GetAPIKey returns the current API key (exported for main.go)
func GetAPIKey() string {
	return getAPIKey()
}

// ValidateKey validates an API key with the backend and returns the plan
func ValidateKey(key string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"key": key})
	req, err := http.NewRequest("POST", getBaseURL()+"/auth/validate-key", bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach backend")
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool   `json:"success"`
		Plan    string `json:"plan"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("invalid response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Plan, nil
}

// SendChat sends prompt with conversation history
func SendChat(prompt string, history []Message) (string, error) {
	return post("/chat", chatRequest{Prompt: prompt, Messages: history})
}

// SendPrompt — simple chat without history
func SendPrompt(prompt string) (string, error) {
	return post("/chat", chatRequest{Prompt: prompt, Messages: []Message{}})
}

// ReconPayload is the structured JSON body sent to /analyze.
type ReconPayload struct {
	Target          string            `json:"target"`
	TargetType      string            `json:"target_type"`
	ToolsRun        []string          `json:"tools_run"`
	ToolsFailed     []string          `json:"tools_failed"`
	ToolsSkipped    []string          `json:"tools_skipped"`
	Findings        map[string]string `json:"findings"`
	SubdomainsFound int               `json:"subdomains_found"`
	LiveHostsFound  int               `json:"live_hosts_found"`
	OpenPorts       []int             `json:"open_ports"`
	WAFDetected     bool              `json:"waf_detected"`
	WAFVendor       string            `json:"waf_vendor"`
	LiveURLs        []string          `json:"live_urls"`
	Technologies    []string          `json:"technologies"`
	RawCombined     string            `json:"raw"`
}

// HuntPayload is the structured JSON body sent to /hunt.
type HuntPayload struct {
	Target         string            `json:"target"`
	TargetType     string            `json:"target_type"`
	ToolsRun       []string          `json:"tools_run"`
	ToolsFailed    []string          `json:"tools_failed"`
	ToolsSkipped   []string          `json:"tools_skipped"`
	Findings       map[string]string `json:"findings"`
	XSSFound       []string          `json:"xss_found"`
	ParamsFound    []string          `json:"params_found"`
	VulnsFound     []string          `json:"vulns_found"`
	HistoricalURLs int               `json:"historical_urls_count"`
	WAFDetected    bool              `json:"waf_detected"`
	WAFVendor      string            `json:"waf_vendor"`
	OpenPorts      []int             `json:"open_ports"`
	RawCombined    string            `json:"raw"`
}

// SendHunt sends structured hunt payload to AI for analysis.
func SendHunt(payload HuntPayload) (string, error) {
	return post("/hunt", payload)
}

// SendAnalysis sends structured recon payload to AI for analysis
func SendAnalysis(payload ReconPayload) (string, error) {
	return post("/analyze", payload)
}

// SendScan — AI-guided scan
func SendScan(target, scanType string) (string, error) {
	return post("/scan", map[string]string{"target": target, "type": scanType})
}

// SendRecon — AI-guided recon
func SendRecon(target, reconType string) (string, error) {
	return post("/recon", map[string]string{"target": target, "type": reconType})
}

// SendExploit — exploitation guide
func SendExploit(vulnerability, target string) (string, error) {
	return post("/exploit", map[string]string{"vulnerability": vulnerability, "target": target})
}

// SendPayload — payload generation guide
func SendPayload(os_, arch, lhost, lport, format string) (string, error) {
	return post("/exploit/payload", map[string]string{
		"os": os_, "arch": arch, "lhost": lhost, "lport": lport, "format": format,
	})
}

// SendAbhimanyu sends findings to Abhimanyu exploit engine
func SendAbhimanyu(target, vulnType string, payload map[string]interface{}) (string, error) {
	payload["target"] = target
	payload["vuln_type"] = vulnType
	return post("/abhimanyu", payload)
}

// SendToolHelp — tool usage guide
func SendToolHelp(tool, task string) (string, error) {
	return post("/tools/help", map[string]string{"tool": tool, "task": task})
}
