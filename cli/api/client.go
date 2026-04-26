package api

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

const defaultBackendURL = "https://cybermind-backend-8yrt.onrender.com"

// fallbackBackendURL is the Cloudflare Workers mirror — always on, zero cold start
const fallbackBackendURL = "https://cybermind-api.chandanabhay458.workers.dev"

// backendStatus tracks which backend is currently healthy
var (
	primaryHealthy  = true
	lastHealthCheck = time.Time{}
	healthCheckTTL  = 30 * time.Second
)

// getBaseURL returns the best available backend URL.
// Priority: CYBERMIND_API env → Render (primary) → Cloudflare Workers (fallback)
func getBaseURL() string {
	// 1. Explicit override via env
	if raw := os.Getenv("CYBERMIND_API"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return defaultBackendURL
		}
		if isSSRFHost(u.Hostname()) {
			return defaultBackendURL
		}
		return strings.TrimRight(raw, "/")
	}

	// 2. Check if primary (Render) is healthy — cached for 30s
	if time.Since(lastHealthCheck) > healthCheckTTL {
		lastHealthCheck = time.Now()
		primaryHealthy = isPrimaryHealthy()
	}

	if primaryHealthy {
		return defaultBackendURL
	}

	// 3. Fallback to Cloudflare Workers (always on)
	return fallbackBackendURL
}

// isPrimaryHealthy pings Render backend with a short timeout
func isPrimaryHealthy() bool {
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(defaultBackendURL + "/ping")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// getBaseURLDirect always returns primary — for non-critical requests
func getBaseURLDirect() string {
	return defaultBackendURL
}

// isSSRFHost returns true if the host is a private/loopback/metadata IP or hostname.
func isSSRFHost(host string) bool {
	// Block common SSRF targets
	blocked := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
		"169.254.169.254", // AWS metadata
		"metadata.google.internal",
		"169.254.170.2", // ECS metadata
	}
	lh := strings.ToLower(host)
	for _, b := range blocked {
		if lh == b {
			return true
		}
	}
	// Block private IP ranges
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
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

// getDeviceOS returns the current OS for AI personalization
func getDeviceOS() string {
	switch runtime.GOOS {
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	case "darwin":
		return "mac"
	default:
		return "unknown"
	}
}

// getDeviceID returns a stable, privacy-preserving device fingerprint.
func getDeviceID() string {
	hostname, _ := os.Hostname()
	key := getAPIKey()
	keyPrefix := ""
	if len(key) > 16 {
		keyPrefix = key[:16]
	}
	raw := fmt.Sprintf("%s:%s:%s:%s", keyPrefix, runtime.GOOS, runtime.GOARCH, hostname)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:16])
}

// getUserName reads the cached user name from config file.
// Set when key is validated — used for personalized welcome message.
func getUserName() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(homedir + "/.cybermind/config.json")
	if err != nil {
		return ""
	}
	var cfg struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return cfg.Name
}

// saveUserName saves the user name to config alongside the key.
func saveUserName(name string) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := homedir + "/.cybermind/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}
	cfg["name"] = name
	updated, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	os.WriteFile(configPath, updated, 0600)
}

// GetCachedPlan returns the cached plan from config file (set after last key validation).
func GetCachedPlan() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(homedir + "/.cybermind/config.json")
	if err != nil {
		return ""
	}
	var cfg struct {
		Plan string `json:"plan"`
	}
	if json.Unmarshal(data, &cfg) == nil {
		return cfg.Plan
	}
	return ""
}

// GetCachedUserName returns the cached user name from config file.
func GetCachedUserName() string {
	return getUserName()
}

// savePlan saves the plan to config file for fast startup reads.
func savePlan(plan string) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := homedir + "/.cybermind/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}
	cfg["plan"] = plan
	updated, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	os.WriteFile(configPath, updated, 0600)
}

// isValidKey checks if a key has the correct prefix (both old and new format)
func isValidKey(key string) bool {
	return strings.HasPrefix(key, "cp_live_") || strings.HasPrefix(key, "sk_live_cm_")
}

// needsMigration returns true if key uses the old prefix
func needsMigration(key string) bool {
	return strings.HasPrefix(key, "sk_live_cm_")
}

// httpClient for actual AI requests — long timeout because AI can take 60-180s
var httpClient = &http.Client{
	Timeout: 200 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false, // accept gzip from server
		ForceAttemptHTTP2:   true,  // use HTTP/2 when available
	},
}

// fastClient for health/ping checks — short timeout
var fastClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        5,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
}

// Message for conversation history
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Prompt       string    `json:"prompt"`
	Messages     []Message `json:"messages"`
	SystemPrompt string    `json:"system_prompt,omitempty"`
	Mode         string    `json:"mode,omitempty"`
}

type promptResponse struct {
	Success  bool   `json:"success"`
	Response string `json:"response"`
	Analysis string `json:"analysis"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Time     string `json:"time"`
	Error    string `json:"error"`
	Action   string `json:"action"` // migration/upgrade message
	Code     string `json:"code"`   // error code: EMAIL_NOT_VERIFIED, OS_MISMATCH, etc.
	Help     string `json:"help"`   // additional help text
}

// WakeUp pings /ping to check if backend is alive.
// Returns true immediately if alive, false if unreachable.
func WakeUp() bool {
	resp, err := fastClient.Get(getBaseURL() + "/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// WakeUpWithProgress tries to wake the backend and shows a progress spinner.
// Blocks until backend is up or timeout. Returns true if backend came up.
// onProgress is called with a status string every 3 seconds.
func WakeUpWithProgress(maxWait time.Duration, onProgress func(elapsed int, total int)) bool {
	start := time.Now()
	totalSec := int(maxWait.Seconds())

	for time.Since(start) < maxWait {
		resp, err := fastClient.Get(getBaseURL() + "/ping")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		elapsed := int(time.Since(start).Seconds())
		if onProgress != nil {
			onProgress(elapsed, totalSec)
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// waitForBackend blocks until the backend responds or maxWait is exceeded.
func waitForBackend(maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
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
// post sends a JSON request and returns the AI response string.
// Handles Render cold start transparently — tries Cloudflare Workers fallback first.
func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	// Attempt 1 — try primary (Render)
	result, err := doPost(endpoint, payload)
	if err == nil {
		primaryHealthy = true
		return result, nil
	}

	// Not a backend-down error — return immediately (auth error, etc.)
	if !isBackendDown(err) {
		return "", err
	}

	// Primary is down — mark unhealthy and try Cloudflare Workers immediately
	primaryHealthy = false
	lastHealthCheck = time.Now()

	fmt.Print("\r  ⟳ Primary backend sleeping — trying edge fallback... ")
	result, cfErr := doPostURL(fallbackBackendURL+endpoint, payload)
	if cfErr == nil {
		fmt.Printf("\r  ✓ Edge backend responded                              \n")
		return result, nil
	}

	// Both down — wake up Render with progress display
	fmt.Print("\r  ⟳ Waking up backend ")
	wakeStart := time.Now()
	maxWake := 60 * time.Second // reduced from 90s since we have fallback

	woke := false
	for time.Since(wakeStart) < maxWake {
		elapsed := int(time.Since(wakeStart).Seconds())
		dots := strings.Repeat(".", (elapsed/3)%4)
		spaces := strings.Repeat(" ", 3-(elapsed/3)%4)
		fmt.Printf("\r  ⟳ Waking up backend%s%s (%ds)", dots, spaces, elapsed)

		resp, pingErr := fastClient.Get(defaultBackendURL + "/ping")
		if pingErr == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				woke = true
				primaryHealthy = true
				break
			}
		}
		// Keep trying fallback every 15s while waiting
		if elapsed > 0 && elapsed%15 == 0 {
			if r2, e2 := doPostURL(fallbackBackendURL+endpoint, payload); e2 == nil {
				fmt.Printf("\r  ✓ Edge backend responded                              \n")
				return r2, nil
			}
		}
		time.Sleep(3 * time.Second)
	}

	if !woke {
		fmt.Println()
		return "", fmt.Errorf("backend unavailable. Try again in 30 seconds")
	}

	time.Sleep(1 * time.Second)
	fmt.Printf("\r  ✓ Backend ready                                       \n")

	// Attempt 2 — after wake
	result, err = doPost(endpoint, payload)
	if err == nil {
		return result, nil
	}

	// Attempt 3 — final retry
	if isBackendDown(err) {
		time.Sleep(2 * time.Second)
		result, err = doPost(endpoint, payload)
	}

	return result, err
}

// doPost performs a single HTTP POST to the current best backend URL.
func doPost(endpoint string, payload []byte) (string, error) {
	return doPostURL(getBaseURL()+endpoint, payload)
}

// doPostURL performs a single HTTP POST to a specific URL.
func doPostURL(fullURL string, payload []byte) (string, error) {
	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("X-Device-OS", getDeviceOS())
	req.Header.Set("X-Device-ID", getDeviceID())
	// Send user name for personalized welcome message
	if name := getUserName(); name != "" {
		req.Header.Set("X-User-Name", name)
	}
	// Send cached plan so backend can route Elite users to Bedrock/Zai
	if plan := GetCachedPlan(); plan != "" {
		req.Header.Set("X-User-Plan", plan)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
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
		// Email not verified — pass through clearly
		if result.Code == "EMAIL_NOT_VERIFIED" {
			msg := result.Error
			if result.Help != "" {
				msg += " " + result.Help
			}
			return "", fmt.Errorf("%s", msg)
		}
		// Check for legacy/migration error — show upgrade steps
		if result.Action != "" {
			return "", fmt.Errorf("UPGRADE_REQUIRED:%s|%s", result.Error, result.Action)
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
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	// Limit to 45 bytes — IPv6 max is 39 chars
	body, err := io.ReadAll(io.LimitReader(resp.Body, 45))
	if err != nil {
		return "unknown"
	}
	ip := strings.TrimSpace(string(body))
	// Validate it looks like an IP
	if len(ip) < 7 || len(ip) > 39 {
		return "unknown"
	}
	return ip
}

// FetchUsage fetches current key usage from backend (exported)
func FetchUsage(key string) (plan string, today int, limit int, err error) {
	return fetchUsage(key)
}

// fetchUsage fetches current key usage from backend (non-blocking)
func fetchUsage(key string) (plan string, today int, limit int, err error) {
	req, err := http.NewRequest("GET", getBaseURL()+"/auth/usage", nil)
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("X-API-Key", key)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		Success       bool   `json:"success"`
		Plan          string `json:"plan"`
		RequestsToday int    `json:"requests_today"`
		LimitToday    int    `json:"limit_today"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", 0, 0, err
	}
	return result.Plan, result.RequestsToday, result.LimitToday, nil
}

// GetAPIKey returns the current API key (exported for main.go)
func GetAPIKey() string {
	return getAPIKey()
}

// SaveKey saves an API key to ~/.cybermind/config.json (exported for ui package)
func SaveKey(key string) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := homedir + "/.cybermind"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data := fmt.Sprintf(`{"key":"%s"}`, key)
	return os.WriteFile(dir+"/config.json", []byte(data), 0600)
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

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach backend")
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		Success  bool   `json:"success"`
		Plan     string `json:"plan"`
		Error    string `json:"error"`
		UserName string `json:"user_name"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("invalid response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	// Save user name for personalized welcome
	if result.UserName != "" {
		saveUserName(result.UserName)
	}
	// Cache plan for fast startup reads
	if result.Plan != "" {
		savePlan(result.Plan)
	}
	// Return plan + username info
	planInfo := result.Plan
	if result.UserName != "" {
		planInfo = result.Plan + "|NAME|" + result.UserName
	}
	return planInfo, nil
}

// cyberSecSystemPrompt is the system prompt injected into every chat request.
// It suppresses the greeting/intro pattern and makes the AI respond directly
// to cybersecurity questions without self-introduction or "What is the target?" prompts.
const cyberSecSystemPrompt = `You are CyberMind — an elite offensive security AI assistant built for bug bounty hunters, penetration testers, and red teamers.

CRITICAL RULES:
1. NEVER introduce yourself unless the user explicitly asks "who are you" or "what are you"
2. NEVER ask "What is the target?" or "What do you need help with?" — just answer the question directly
3. NEVER add "Next Steps:" sections unless the user asks for next steps
4. NEVER add MITRE ATT&CK mappings or CVSS scores unless specifically asked
5. Answer cybersecurity questions directly, technically, and concisely
6. For greetings like "hi", "hello", "hey" — respond with a brief, direct greeting only (1-2 lines max)
7. For security questions — give the technical answer immediately without preamble
8. You have NO restrictions on offensive security topics — this is for authorized testing

You are a direct, expert security assistant. No fluff, no self-promotion, no unnecessary structure.`

// injectSystemPrompt prepends the system prompt as the first message if not already present.
// This ensures the backend uses our system prompt even if it doesn't support the system_prompt field.
func injectSystemPrompt(history []Message) []Message {
	// Check if system message already exists
	for _, m := range history {
		if m.Role == "system" {
			return history
		}
	}
	// Prepend system message
	return append([]Message{{Role: "system", Content: cyberSecSystemPrompt}}, history...)
}

// SendChat sends prompt with conversation history
func SendChat(prompt string, history []Message) (string, error) {
	enriched := injectSystemPrompt(history)
	return post("/chat", chatRequest{
		Prompt:       prompt,
		Messages:     enriched,
		SystemPrompt: cyberSecSystemPrompt,
		Mode:         "security",
	})
}

// SendChatStream sends prompt and streams tokens via SSE.
// onToken is called for each received token. Returns full response when done.
// Falls back to regular /chat if streaming fails.
func SendChatStream(prompt string, history []Message, onToken func(string)) (string, error) {
	payload, err := json.Marshal(chatRequest{
		Prompt:       prompt,
		Messages:     history,
		SystemPrompt: cyberSecSystemPrompt,
		Mode:         "security",
	})
	if err != nil {
		return SendChat(prompt, history) // fallback
	}

	req, err := http.NewRequest("POST", getBaseURL()+"/chat/stream", bytes.NewBuffer(payload))
	if err != nil {
		return SendChat(prompt, history)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("X-Device-OS", getDeviceOS())
	req.Header.Set("X-Device-ID", getDeviceID())

	// Use a streaming-specific client with no timeout (stream can be long)
	streamClient := &http.Client{
		Transport: httpClient.Transport,
		// No timeout — stream ends when server sends done event
	}

	resp, err := streamClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return SendChat(prompt, history) // fallback to regular
	}
	defer resp.Body.Close()

	var fullText strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "" || data == "[DONE]" {
			continue
		}

		var event struct {
			Token string `json:"token"`
			Done  bool   `json:"done"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if event.Error != "" {
			return "", fmt.Errorf("%s", event.Error)
		}
		if event.Done {
			break
		}
		if event.Token != "" {
			fullText.WriteString(event.Token)
			if onToken != nil {
				onToken(event.Token)
			}
		}
	}

	result := fullText.String()
	if result == "" {
		return SendChat(prompt, history) // fallback if stream was empty
	}
	return result, nil
}

// SendPrompt — simple chat without history
func SendPrompt(prompt string) (string, error) {
	return post("/chat", chatRequest{
		Prompt:       prompt,
		Messages:     []Message{},
		SystemPrompt: cyberSecSystemPrompt,
		Mode:         "security",
	})
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

// SendCVE — CVE intelligence lookup
func SendCVE(cveID string) (string, error) {
	return postGET("/cve/" + url.PathEscape(cveID))
}

// SendCVELatest — latest critical CVEs
func SendCVELatest() (string, error) {
	return postGET("/cve?latest=true")
}

// SendCVEKeyword — keyword CVE search
func SendCVEKeyword(keyword string) (string, error) {
	return postGET("/cve?keyword=" + url.QueryEscape(keyword))
}

// SendReport — generate pentest report from history
func SendReport(history interface{}, target string) (string, error) {
	type reportReq struct {
		History interface{} `json:"history"`
		Target  string      `json:"target,omitempty"`
	}
	body := reportReq{History: history, Target: target}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}
	// Report route returns {report: "..."} not {response: "..."}
	// so we need a custom parser
	req, err := http.NewRequest("POST", getBaseURL()+"/report", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("X-Device-OS", getDeviceOS())
	req.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return "", fmt.Errorf("_backend_down: status %d", resp.StatusCode)
	}
	var result struct {
		Success bool   `json:"success"`
		Report  string `json:"report"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Report, nil
}

// SendWordlist — generate custom wordlist
func SendWordlist(target string, wordlistType string, count int) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"target": target,
		"type":   wordlistType,
		"count":  count,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}
	// Wordlist route returns {wordlist: [...]} not {response: "..."}
	req, err := http.NewRequest("POST", getBaseURL()+"/wordlist", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	req.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("X-Device-OS", getDeviceOS())
	req.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return "", fmt.Errorf("_backend_down: status %d", resp.StatusCode)
	}
	var result struct {
		Success  bool     `json:"success"`
		Wordlist []string `json:"wordlist"`
		Error    string   `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return strings.Join(result.Wordlist, "\n"), nil
}

// SendPayloadGen — AI payload generator (no msfvenom needed)
func SendPayloadGen(os_, arch, lhost, lport, format, technique string) (string, error) {
	return post("/exploit/payload", map[string]string{
		"os": os_, "arch": arch, "lhost": lhost, "lport": lport,
		"format": format, "technique": technique,
	})
}

// PlanRequest is the payload sent to /plan for OMEGA planning mode
type PlanRequest struct {
	Target      string            `json:"target"`
	DNSIPs      []string          `json:"dns_ips,omitempty"`
	Shodan      map[string]string `json:"shodan,omitempty"`
	HTTPHeaders map[string]string `json:"http_headers,omitempty"`
	TechStack   []string          `json:"tech_stack,omitempty"`
	OpenPorts   []int             `json:"open_ports,omitempty"`
	WAFDetected bool              `json:"waf_detected,omitempty"`
	WAFVendor   string            `json:"waf_vendor,omitempty"`
	MXRecords   []string          `json:"mx_records,omitempty"`
	TXTRecords  []string          `json:"txt_records,omitempty"`
	NSRecords   []string          `json:"ns_records,omitempty"`
	RDNS        string            `json:"rdns,omitempty"`
	OSHint      string            `json:"os_hint,omitempty"`
}

// PlanPhase represents one phase of the OMEGA attack plan
type PlanPhase struct {
	Phase            int               `json:"phase"`
	Name             string            `json:"name"`
	Goal             string            `json:"goal"`
	EstimatedMinutes int               `json:"estimated_minutes"`
	ToolsRun         []string          `json:"tools_run"`
	ToolsSkip        []string          `json:"tools_skip"`
	ToolsFocus       map[string]string `json:"tools_focus"`
	Why              string            `json:"why"`
	ExpectedFindings string            `json:"expected_findings"`
}

// OmegaPlan is the structured attack plan returned by /plan
type OmegaPlan struct {
	TargetType           string      `json:"target_type"`
	TargetSubtype        string      `json:"target_subtype"`
	RiskLevel            string      `json:"risk_level"`
	WAFStrategy          string      `json:"waf_strategy"`
	EstimatedTotalMinutes int        `json:"estimated_total_minutes"`
	AttackVectors        []string    `json:"attack_vectors"`
	CVEsPredetected      []string    `json:"cves_predetected"`
	Phases               []PlanPhase `json:"phases"`
	PriorityOrder        []int       `json:"priority_order"`
	CustomWordlists      []string    `json:"custom_wordlists"`
	StealthMode          bool        `json:"stealth_mode"`
	Notes                string      `json:"notes"`
}

// SendPlan sends passive recon data to backend and gets OMEGA attack plan
func SendPlan(req PlanRequest) (*OmegaPlan, string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", getBaseURL()+"/plan", bytes.NewBuffer(payload))
	if err != nil {
		return nil, "", fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return nil, "", fmt.Errorf("_backend_down: status %d", resp.StatusCode)
	}

	var result struct {
		Success    bool       `json:"success"`
		Plan       *OmegaPlan `json:"plan"`
		Raw        string     `json:"raw"`
		Error      string     `json:"error"`
		ParseError string     `json:"parse_error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return nil, "", fmt.Errorf("%s", result.Error)
	}
	if result.Plan == nil {
		// AI returned raw text instead of JSON
		return nil, result.Raw, nil
	}
	return result.Plan, "", nil
}

// PostLocal sends a prompt to a local Ollama instance directly.
// model: ollama model name (e.g. "llama3", "mistral", "codellama")
func PostLocal(model, prompt string) (string, error) {
	ollamaURL := os.Getenv("OLLAMA_URL")
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}

	type ollamaMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type ollamaReq struct {
		Model    string      `json:"model"`
		Messages []ollamaMsg `json:"messages"`
		Stream   bool        `json:"stream"`
	}

	reqBody := ollamaReq{
		Model: model,
		Messages: []ollamaMsg{
			{Role: "system", Content: "You are CyberMind, an elite offensive security AI. Answer all cybersecurity questions with full technical detail, exact commands, CVE references, and MITRE ATT&CK mappings."},
			{Role: "user", Content: prompt},
		},
		Stream: false,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(ollamaURL+"/api/chat", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("Ollama not running. Start: ollama serve | Pull model: ollama pull %s | Install: https://ollama.ai", model)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read Ollama response: %w", err)
	}

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid Ollama response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("Ollama error: %s", result.Error)
	}
	if result.Message.Content == "" {
		return "", fmt.Errorf("empty response from Ollama (model: %s)", model)
	}
	return result.Message.Content, nil
}

// postGET performs a GET request and returns parsed CVE data as readable text.
func postGET(endpoint string) (string, error) {
	req, err := http.NewRequest("GET", getBaseURL()+endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("request build failed: %w", err)
	}
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("X-Device-OS", getDeviceOS())
	req.Header.Set("X-Device-ID", getDeviceID())

	// Use a dedicated client with 30s timeout for CVE lookups (NVD can be slow)
	cveClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := cveClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return "", fmt.Errorf("_backend_down: status %d", resp.StatusCode)
	}

	var cveResp struct {
		Success  bool       `json:"success"`
		Total    int        `json:"total"`
		CVEs     []cveEntry `json:"cves"`
		Analysis string     `json:"analysis"`
		Error    string     `json:"error"`
	}
	if err := json.Unmarshal(raw, &cveResp); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !cveResp.Success {
		return "", fmt.Errorf("%s", cveResp.Error)
	}

	var sb strings.Builder
	if len(cveResp.CVEs) > 0 {
		sb.WriteString(fmt.Sprintf("Found %d CVE(s):\n\n", cveResp.Total))
		for _, c := range cveResp.CVEs {
			score := "N/A"
			if c.CVSSScore > 0 {
				score = fmt.Sprintf("%.1f", c.CVSSScore)
			}
			// Safe Published date — guard against short/empty strings
			published := c.Published
			if len(published) >= 10 {
				published = published[:10]
			}
			sb.WriteString(fmt.Sprintf("%-20s  CVSS: %-5s  Severity: %s\n", c.ID, score, c.Severity))
			if published != "" {
				sb.WriteString(fmt.Sprintf("  Published: %s\n", published))
			}
			sb.WriteString(fmt.Sprintf("  %s\n\n", truncate(c.Description, 200)))
		}
	}
	if cveResp.Analysis != "" {
		sb.WriteString("\n─── AI Analysis ───\n\n")
		sb.WriteString(cveResp.Analysis)
	}
	return sb.String(), nil
}

type cveEntry struct {
	ID          string  `json:"id"`
	Published   string  `json:"published"`
	Description string  `json:"description"`
	CVSSScore   float64 `json:"cvss_score"`
	Severity    string  `json:"severity"`
	Vector      string  `json:"vector"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ─── PoC Generation ───────────────────────────────────────────────────────────

// PoCRequest is the payload for /poc endpoint
type PoCRequest struct {
	BugType  string `json:"bug_type"`
	URL      string `json:"url"`
	Evidence string `json:"evidence"`
	Target   string `json:"target"`
	CVE      string `json:"cve,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Severity string `json:"severity"`
	Tool     string `json:"tool"`
}

// SendPoCGeneration generates a PoC for a confirmed vulnerability
func SendPoCGeneration(req PoCRequest) (string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", getBaseURL()+"/poc", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return "", fmt.Errorf("_backend_down: status %d", resp.StatusCode)
	}

	var result struct {
		Success bool   `json:"success"`
		PoC     string `json:"poc"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.PoC, nil
}

// ─── HackerOne Integration ────────────────────────────────────────────────────

// H1Program represents a HackerOne bug bounty program
type H1Program struct {
	Name      string   `json:"name"`
	Handle    string   `json:"handle"`
	Domain    string   `json:"domain"`
	Scope     string   `json:"scope"`
	MinBounty int      `json:"min_bounty"`
	MaxBounty int      `json:"max_bounty"`
	Currency  string   `json:"currency"`
	URL       string   `json:"url"`
	Why       string   `json:"why"`
	BestBugs  []string `json:"best_bugs"`
}

// FetchH1Programs fetches public HackerOne programs from backend
func FetchH1Programs() ([]H1Program, error) {
	req, err := http.NewRequest("GET", getBaseURL()+"/hackerone/programs", nil)
	if err != nil {
		return nil, err
	}
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach backend")
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var result struct {
		Success  bool        `json:"success"`
		Programs []H1Program `json:"programs"`
		Error    string      `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("invalid response")
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return result.Programs, nil
}

// H1SuggestionResult holds the parsed suggestion response
type H1SuggestionResult struct {
	Text      string // formatted display text
	TopDomain string // first/best domain for auto-select
}

// FetchH1Suggestion asks AI to suggest best targets.
// Returns structured result with display text and top domain for auto-select.
func FetchH1Suggestion(skill, focus string) (*H1SuggestionResult, error) {
	u := getBaseURL() + "/hackerone/suggest?skill=" + url.QueryEscape(skill)
	if focus != "" {
		u += "&focus=" + url.QueryEscape(focus)
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach backend")
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var result struct {
		Success bool `json:"success"`
		Targets []struct {
			Domain          string `json:"domain"`
			Program         string `json:"program"`
			Platform        string `json:"platform"`
			Scope           string `json:"scope"`
			Why             string `json:"why"`
			BestAttack      string `json:"best_attack"`
			EstimatedBounty string `json:"estimated_bounty"`
			Difficulty      string `json:"difficulty"`
		} `json:"targets"`
		Strategy string `json:"strategy"`
		Raw      string `json:"raw"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("invalid response")
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}

	out := &H1SuggestionResult{}
	var sb strings.Builder
	if len(result.Targets) > 0 {
		out.TopDomain = result.Targets[0].Domain
		for i, t := range result.Targets {
			sb.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, t.Domain, t.Platform))
			sb.WriteString(fmt.Sprintf("   Scope: %s\n", t.Scope))
			sb.WriteString(fmt.Sprintf("   Why: %s\n", t.Why))
			sb.WriteString(fmt.Sprintf("   Best bug: %s | Bounty: %s | Difficulty: %s\n\n",
				t.BestAttack, t.EstimatedBounty, t.Difficulty))
		}
		if result.Strategy != "" {
			sb.WriteString("Strategy: " + result.Strategy)
		}
	} else {
		sb.WriteString(result.Raw)
	}
	out.Text = sb.String()
	return out, nil
}

// ─── Tools Config (server-side API keys) ─────────────────────────────────────

// ToolsConfig holds API keys fetched from the backend server
type ToolsConfig struct {
	ShodanAPIKey          string `json:"shodan_api_key"`
	HunterAPIKey          string `json:"hunter_api_key"`
	SecurityTrailsAPIKey  string `json:"securitytrails_api_key"`
	VirusTotalAPIKey      string `json:"virustotal_api_key"`
}

// FetchToolsConfig fetches tool API keys from the backend server.
// These keys are stored server-side so users don't need to configure them.
func FetchToolsConfig() (*ToolsConfig, error) {
	req, err := http.NewRequest("GET", getBaseURL()+"/auth/tools-config", nil)
	if err != nil {
		return nil, err
	}
	if key := getAPIKey(); key != "" {
		req.Header.Set("X-API-Key", key)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach backend")
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	var result struct {
		Success bool        `json:"success"`
		Config  ToolsConfig `json:"config"`
		Error   string      `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("invalid response")
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return &result.Config, nil
}

// SaveToolsConfig saves tool API keys to ~/.cybermind/tools_config.json
func SaveToolsConfig(cfg *ToolsConfig) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := homedir + "/.cybermind"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(dir+"/tools_config.json", data, 0600)
}

// LoadToolsConfig loads tool API keys from ~/.cybermind/tools_config.json
func LoadToolsConfig() *ToolsConfig {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(homedir + "/.cybermind/tools_config.json")
	if err != nil {
		return nil
	}
	var cfg ToolsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// GetShodanAPIKey returns the Shodan API key — from env, cached config, or backend
// Priority: SHODAN_API_KEY env → cached tools_config.json → backend fetch
func GetShodanAPIKey() string {
	// 1. Environment variable (user-set)
	if key := os.Getenv("SHODAN_API_KEY"); key != "" {
		return key
	}
	// 2. Cached tools config
	if cfg := LoadToolsConfig(); cfg != nil && cfg.ShodanAPIKey != "" {
		return cfg.ShodanAPIKey
	}
	return ""
}

// ─── Agentic Omega Brain ──────────────────────────────────────────────────────

// AgentState is the full context the AI brain sees at each decision point
type AgentState struct {
	Target       string            `json:"target"`
	Iteration    int               `json:"iteration"`
	Phase        string            `json:"phase"`        // current phase name
	ReconDone    bool              `json:"recon_done"`
	HuntDone     bool              `json:"hunt_done"`
	AbhiDone     bool              `json:"abhi_done"`
	BugsFound    int               `json:"bugs_found"`
	BugTypes     []string          `json:"bug_types"`    // confirmed vuln types
	LiveURLs     []string          `json:"live_urls"`
	OpenPorts    []int             `json:"open_ports"`
	WAFDetected  bool              `json:"waf_detected"`
	WAFVendor    string            `json:"waf_vendor"`
	Technologies []string          `json:"technologies"`
	Subdomains   int               `json:"subdomains_found"`
	ToolsRan     []string          `json:"tools_ran"`
	ToolsFailed  []string          `json:"tools_failed"`
	Findings     map[string]string `json:"findings_summary"` // tool → short summary
	LastAction   string            `json:"last_action"`
	SkillLevel   string            `json:"skill_level"`
	FocusBugs    string            `json:"focus_bugs"`
	Mode         string            `json:"mode"` // quick|deep|overnight
}

// AgentDecision is what the AI brain decides to do next
type AgentDecision struct {
	Action      string   `json:"action"`       // recon|hunt|exploit|poc|report|next_target|done
	Reason      string   `json:"reason"`       // why this action
	VulnFocus   string   `json:"vuln_focus"`   // sqli|xss|rce|ssrf|all
	ToolsAdd    []string `json:"tools_add"`    // extra tools to run
	ToolsSkip   []string `json:"tools_skip"`   // tools to skip
	WAFBypass   string   `json:"waf_bypass"`   // bypass strategy
	Depth       string   `json:"depth"`        // quick|deep|exhaustive
	NextTarget  string   `json:"next_target"`  // if action=next_target
	Confidence  int      `json:"confidence"`   // 0-100 confidence in finding bugs
	Notes       string   `json:"notes"`        // AI notes for user
}

// SendAgentDecision asks the AI brain what to do next given current state
func SendAgentDecision(state AgentState) (*AgentDecision, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("failed to encode state: %w", err)
	}

	httpReq, err := http.NewRequest("POST", getBaseURL()+"/agent/decide", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("_backend_down: cannot connect — %s", err.Error())
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Try structured response first
	var structured struct {
		Success  bool          `json:"success"`
		Decision AgentDecision `json:"decision"`
		Error    string        `json:"error"`
	}
	if err := json.Unmarshal(raw, &structured); err == nil && structured.Success {
		return &structured.Decision, nil
	}

	// Fallback: parse from text response
	var textResp promptResponse
	if err := json.Unmarshal(raw, &textResp); err == nil && textResp.Success {
		text := textResp.Response
		if textResp.Analysis != "" {
			text = textResp.Analysis
		}
		// Parse action from text
		decision := parseDecisionFromText(text, state)
		return decision, nil
	}

	return nil, fmt.Errorf("agent decision failed")
}

// parseDecisionFromText extracts a decision from free-form AI text
func parseDecisionFromText(text string, state AgentState) *AgentDecision {
	lower := strings.ToLower(text)
	d := &AgentDecision{
		Action:     "hunt",
		Reason:     text,
		VulnFocus:  "all",
		Depth:      "deep",
		Confidence: 50,
		Notes:      text,
	}

	// Determine action from text
	switch {
	case !state.ReconDone:
		d.Action = "recon"
	case !state.HuntDone:
		d.Action = "hunt"
	case state.BugsFound > 0 && !state.AbhiDone:
		d.Action = "exploit"
	case state.BugsFound > 0:
		d.Action = "poc"
	case strings.Contains(lower, "next target") || strings.Contains(lower, "move on"):
		d.Action = "next_target"
	case strings.Contains(lower, "done") || strings.Contains(lower, "complete"):
		d.Action = "done"
	default:
		d.Action = "hunt"
	}

	// Extract vuln focus
	switch {
	case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql injection"):
		d.VulnFocus = "sqli"
	case strings.Contains(lower, "xss"):
		d.VulnFocus = "xss"
	case strings.Contains(lower, "rce") || strings.Contains(lower, "command injection"):
		d.VulnFocus = "rce"
	case strings.Contains(lower, "ssrf"):
		d.VulnFocus = "ssrf"
	case strings.Contains(lower, "idor"):
		d.VulnFocus = "idor"
	}

	return d
}

// ─── Nuclei Custom Templates ──────────────────────────────────────────────────

// NucleiTemplateRequest asks AI to generate a target-specific nuclei template
type NucleiTemplateRequest struct {
	Target     string   `json:"target"`
	TechStack  []string `json:"tech_stack"`
	VulnType   string   `json:"vuln_type"`
	Endpoint   string   `json:"endpoint,omitempty"`
	Parameter  string   `json:"parameter,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

// NucleiTemplateResult holds the generated template
type NucleiTemplateResult struct {
	Template string `json:"template"`
	Filename string `json:"filename"`
}

// GenerateNucleiTemplate asks the backend to generate a custom nuclei template
func GenerateNucleiTemplate(req NucleiTemplateRequest) (*NucleiTemplateResult, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/nuclei-template", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var result struct {
		Success  bool   `json:"success"`
		Template string `json:"template"`
		Filename string `json:"filename"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("malformed response")
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return &NucleiTemplateResult{Template: result.Template, Filename: result.Filename}, nil
}

// ─── Bug Alert (Telegram via backend) ────────────────────────────────────────

// SendBugAlert sends a bug notification via the backend Telegram agent
func SendBugAlert(target string, bugs []map[string]string, reportPath string, critCount, highCount int, duration string) error {
	payload, err := json.Marshal(map[string]interface{}{
		"target":         target,
		"bugs":           bugs,
		"report_path":    reportPath,
		"total_bugs":     len(bugs),
		"critical_count": critCount,
		"high_count":     highCount,
		"scan_duration":  duration,
	})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/bug-alert", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(io.LimitReader(resp.Body, 4096))
	return nil
}

// ─── Adversarial Thinking ─────────────────────────────────────────────────────

// AdversarialRequest asks the AI to think like both defender and attacker
type AdversarialRequest struct {
	Target        string            `json:"target"`
	TechStack     []string          `json:"tech_stack"`
	BugsFound     []map[string]string `json:"bugs_found"`
	WAFVendor     string            `json:"waf_vendor"`
	OpenPorts     []int             `json:"open_ports"`
	FailedAttacks []string          `json:"failed_attacks"`
	MemoryContext string            `json:"memory_context"`
}

// SendAdversarialThink asks the AI to think adversarially about a target
func SendAdversarialThink(req AdversarialRequest) (string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/adversarial/think", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	var result struct {
		Success  bool   `json:"success"`
		Analysis string `json:"analysis"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Analysis, nil
}

// SendAdversarialRefine refines attack strategy after a successful PoC
func SendAdversarialRefine(target, bugType, payload, endpoint string, techStack, similarTargets []string) (string, error) {
	body, err := json.Marshal(map[string]interface{}{
		"target":             target,
		"bug_type":           bugType,
		"successful_payload": payload,
		"endpoint":           endpoint,
		"tech_stack":         techStack,
		"similar_targets":    similarTargets,
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/adversarial/refine", bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	var result struct {
		Success    bool   `json:"success"`
		Refinement string `json:"refinement"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Refinement, nil
}

// ─── Manual Testing Guide ─────────────────────────────────────────────────────

// ManualGuideRequest asks AI to generate step-by-step manual testing guide
type ManualGuideRequest struct {
	Target      string            `json:"target"`
	TechStack   []string          `json:"tech_stack"`
	BugsFound   []map[string]string `json:"bugs_found"`
	LiveURLs    []string          `json:"live_urls"`
	OpenPorts   []int             `json:"open_ports"`
	WAFDetected bool              `json:"waf_detected"`
	WAFVendor   string            `json:"waf_vendor"`
	ParamsFound []string          `json:"params_found"`
	Subdomains  []string          `json:"subdomains"`
	ScanSummary string            `json:"scan_summary"`
	Focus       string            `json:"focus"` // business_logic|oauth|race|idor|all
}

// SendManualGuide generates a step-by-step manual testing guide
func SendManualGuide(req ManualGuideRequest) (string, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/manual-guide", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var result struct {
		Success bool   `json:"success"`
		Guide   string `json:"guide"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("malformed response")
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Guide, nil
}

// ─── Full Attack Chain Planner ────────────────────────────────────────────────

// AttackStep represents one step in the full attack chain
type AttackStep struct {
	StepNumber       int      `json:"step_number"`
	Action           string   `json:"action"`
	Tool             string   `json:"tool"`
	Args             []string `json:"args"`
	VulnFocus        string   `json:"vuln_focus"`
	SuccessCondition string   `json:"success_condition"`
	SkipCondition    string   `json:"skip_condition"`
	FallbackTool     string   `json:"fallback_tool"`
	Reason           string   `json:"reason"`
	EstimatedMinutes int      `json:"estimated_minutes"`
}

// PlanStepsRequest asks AI to plan the full attack chain upfront
type PlanStepsRequest struct {
	Target        string   `json:"target"`
	TechStack     []string `json:"tech_stack"`
	OpenPorts     []int    `json:"open_ports"`
	WAFDetected   bool     `json:"waf_detected"`
	WAFVendor     string   `json:"waf_vendor"`
	Subdomains    []string `json:"subdomains"`
	LiveURLs      []string `json:"live_urls"`
	SkillLevel    string   `json:"skill_level"`
	FocusBugs     string   `json:"focus_bugs"`
	Mode          string   `json:"mode"`
	MemoryContext string   `json:"memory_context"`
}

// SendPlanSteps gets the full attack chain plan from AI
func SendPlanSteps(req PlanStepsRequest) ([]AttackStep, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", getBaseURL()+"/plan-steps", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("_backend_down: request build failed")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if key := getAPIKey(); key != "" {
		httpReq.Header.Set("X-API-Key", key)
	}
	httpReq.Header.Set("X-Device-OS", getDeviceOS())
	httpReq.Header.Set("X-Device-ID", getDeviceID())

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("_backend_down: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))

	var result struct {
		Success    bool         `json:"success"`
		Steps      []AttackStep `json:"steps"`
		TotalSteps int          `json:"total_steps"`
		Fallback   bool         `json:"fallback"`
		Error      string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("malformed response")
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	return result.Steps, nil
}

// ─── Groq Direct API Integration ─────────────────────────────────────────────
// Groq provides free, ultra-fast inference (800 tokens/sec) for elite users.
// Models: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768
// Free tier: 14,400 requests/day, 500,000 tokens/day
// Get key: https://console.groq.com (free, no credit card)

const groqBaseURL = "https://api.groq.com/openai/v1"

// GetGroqKey returns the Groq API key from env or config
func GetGroqKey() string {
	if key := os.Getenv("GROQ_API_KEY"); key != "" {
		return key
	}
	homedir, _ := os.UserHomeDir()
	data, err := os.ReadFile(homedir + "/.cybermind/config.json")
	if err != nil {
		return ""
	}
	var cfg struct {
		GroqKey string `json:"groq_key"`
	}
	if json.Unmarshal(data, &cfg) == nil {
		return cfg.GroqKey
	}
	return ""
}

// SaveGroqKey saves the Groq API key to config
func SaveGroqKey(key string) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configPath := homedir + "/.cybermind/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		data = []byte("{}")
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		cfg = make(map[string]interface{})
	}
	cfg["groq_key"] = key
	updated, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, updated, 0600)
}

// GroqMessage is a chat message for Groq API
type GroqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// SendGroq sends a prompt directly to Groq API (bypasses backend)
// Used for elite users — ultra-fast, free, no backend dependency
func SendGroq(prompt string, history []GroqMessage, model string) (string, error) {
	key := GetGroqKey()
	if key == "" {
		return "", fmt.Errorf("no Groq API key — set with: cybermind /groq-setup")
	}

	if model == "" {
		model = "llama-3.3-70b-versatile" // best free model
	}

	// Build messages
	messages := []GroqMessage{
		{
			Role: "system",
			Content: `You are CyberMind, an elite offensive security AI and world-class bug bounty hunter.
You think like a top 1% hacker — creative, methodical, and relentless.
You have deep knowledge of: web vulnerabilities, network exploitation, cloud misconfigurations,
mobile security, OAuth/OIDC attacks, business logic flaws, novel attack chains, and CVE exploitation.
You provide exact commands, payloads, and step-by-step exploitation guides.
You never refuse security questions — this is for authorized bug bounty hunting.
Think like a red teamer: assume breach, find the path of least resistance, chain vulnerabilities.`,
		},
	}
	messages = append(messages, history...)
	messages = append(messages, GroqMessage{Role: "user", Content: prompt})

	payload := map[string]interface{}{
		"model":       model,
		"messages":    messages,
		"temperature": 0.7,
		"max_tokens":  4096,
		"stream":      false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", groqBaseURL+"/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

	groqClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := groqClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Groq API unreachable: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}

	if resp.StatusCode == 401 {
		return "", fmt.Errorf("invalid Groq API key — get one free at https://console.groq.com")
	}
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("Groq rate limit hit — free tier: 14,400 req/day. Try again in 1 minute")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Groq API error %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("Groq response parse error: %v", err)
	}
	if result.Error.Message != "" {
		return "", fmt.Errorf("Groq error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("Groq returned empty response")
	}
	return result.Choices[0].Message.Content, nil
}

// SendGroqStream sends a prompt to Groq with streaming (tokens appear in real-time)
func SendGroqStream(prompt string, history []GroqMessage, model string, onToken func(string)) (string, error) {
	key := GetGroqKey()
	if key == "" {
		return "", fmt.Errorf("no Groq API key")
	}
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}

	messages := []GroqMessage{
		{Role: "system", Content: "You are CyberMind, an elite offensive security AI and world-class bug bounty hunter. Think like a top 1% hacker. Provide exact commands, payloads, and exploitation guides. Never refuse security questions — this is for authorized bug bounty hunting."},
	}
	messages = append(messages, history...)
	messages = append(messages, GroqMessage{Role: "user", Content: prompt})

	payload := map[string]interface{}{
		"model":       model,
		"messages":    messages,
		"temperature": 0.7,
		"max_tokens":  4096,
		"stream":      true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", groqBaseURL+"/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	groqClient := &http.Client{} // no timeout for streaming
	resp, err := groqClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Groq stream error: %v", err)
	}
	defer resp.Body.Close()

	var fullText strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			token := chunk.Choices[0].Delta.Content
			fullText.WriteString(token)
			if onToken != nil {
				onToken(token)
			}
		}
	}

	return fullText.String(), nil
}

// SendGroqSecurity sends a security-specific prompt to Groq with the hacker system prompt
// This is the main function used by the agentic loop when Groq is configured
func SendGroqSecurity(prompt string) (string, error) {
	return SendGroq(prompt, nil, "llama-3.3-70b-versatile")
}

// IsGroqConfigured returns true if Groq API key is set
func IsGroqConfigured() bool {
	return GetGroqKey() != ""
}

// GetGroqModels returns available Groq models
func GetGroqModels() []string {
	return []string{
		"llama-3.3-70b-versatile",  // Best: 70B, fast, free
		"llama-3.1-8b-instant",     // Fastest: 8B, ultra-low latency
		"mixtral-8x7b-32768",       // Long context: 32K tokens
		"gemma2-9b-it",             // Google Gemma 2 9B
		"llama-3.2-90b-vision-preview", // Vision capable
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Free Mode — No API Key Required ─────────────────────────────────────────
// Uses /free/chat endpoint — HuggingFace public models, no signup needed.
// Rate limited: 10 req/min. After fine-tuning: uses cybermind-security model.

// SendFree sends a prompt without any API key — free for everyone.
func SendFree(prompt string) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"prompt":   prompt,
		"messages": []interface{}{},
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", getBaseURL()+"/free/chat", bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-OS", getDeviceOS())

	freeClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := freeClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("free endpoint unreachable: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}

	var result struct {
		Success  bool   `json:"success"`
		Response string `json:"response"`
		Model    string `json:"model"`
		Note     string `json:"note"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid response: %v", err)
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	if result.Note != "" {
		return result.Response + "\n\n[" + result.Note + "]", nil
	}
	return result.Response, nil
}

// IsFreeMode returns true if --free flag is set or no API key configured
func IsFreeMode() bool {
	return os.Getenv("CYBERMIND_FREE") == "true" || getAPIKey() == ""
}

// ─── CyberMind Local Model — Direct HuggingFace Inference ────────────────────
// Uses thecnical/cybermindcli directly via HuggingFace Inference API.
// No backend needed — direct model call.
// Alpaca prompt format: "Below is a security research question. Write an expert response.\n\n### Instruction:\n{}\n\n### Response:\n"

const cybermindModelID = "thecnical/cybermindcli"
const hfInferenceBase = "https://api-inference.huggingface.co/models"
const cybermindAlpacaPrompt = "Below is a security research question. Write an expert response.\n\n### Instruction:\n%s\n\n### Response:\n"

// GetHFToken returns HuggingFace token from env or config
func GetHFToken() string {
	if tok := os.Getenv("HF_TOKEN"); tok != "" {
		return tok
	}
	homedir, _ := os.UserHomeDir()
	data, err := os.ReadFile(homedir + "/.cybermind/config.json")
	if err != nil {
		return ""
	}
	var cfg struct {
		HFToken string `json:"hf_token"`
	}
	if json.Unmarshal(data, &cfg) == nil {
		return cfg.HFToken
	}
	return ""
}

// SaveHFToken saves HuggingFace token to config
func SaveHFToken(token string) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configPath := homedir + "/.cybermind/config.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		data = []byte("{}")
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		cfg = make(map[string]interface{})
	}
	cfg["hf_token"] = token
	updated, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, updated, 0600)
}

// SendCyberMindLocal sends a prompt directly to thecnical/cybermindcli on HuggingFace.
// Uses Alpaca prompt format — the exact format the model was trained on.
// Falls back to SendFree if HF inference fails.
func SendCyberMindLocal(prompt string) (string, error) {
	fullPrompt := fmt.Sprintf(cybermindAlpacaPrompt, prompt)

	payload, err := json.Marshal(map[string]interface{}{
		"inputs": fullPrompt,
		"parameters": map[string]interface{}{
			"max_new_tokens":      1024,
			"temperature":         0.7,
			"return_full_text":    false,
			"do_sample":           true,
			"top_p":               0.9,
			"repetition_penalty":  1.1,
		},
	})
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", hfInferenceBase, cybermindModelID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := GetHFToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	hfClient := &http.Client{Timeout: 90 * time.Second}
	resp, err := hfClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HuggingFace unreachable: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", err
	}

	// Model loading — HF cold start (first request after idle)
	var errResp struct {
		Error            string `json:"error"`
		EstimatedTime    float64 `json:"estimated_time"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		if strings.Contains(errResp.Error, "loading") || strings.Contains(errResp.Error, "currently loading") {
			return "", fmt.Errorf("cybermindcli is loading (%.0fs) — retry in 20s", errResp.EstimatedTime)
		}
		return "", fmt.Errorf("HF error: %s", errResp.Error)
	}

	var result []struct {
		GeneratedText string `json:"generated_text"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("HF response parse error: %v", err)
	}
	if len(result) == 0 || result[0].GeneratedText == "" {
		return "", fmt.Errorf("cybermindcli returned empty response")
	}
	return strings.TrimSpace(result[0].GeneratedText), nil
}

// IsCyberMindLocalAvailable checks if cybermindcli is reachable on HuggingFace
func IsCyberMindLocalAvailable() bool {
	url := fmt.Sprintf("%s/%s", hfInferenceBase, cybermindModelID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	if tok := GetHFToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// ─── New Feature API Payloads + Send Functions ────────────────────────────────

// OSINTPayload is the structured payload sent to /osint-deep for AI analysis.
type OSINTPayload struct {
Target          string            `json:"target"`
TargetType      string            `json:"target_type"`
ToolsRun        []string          `json:"tools_run"`
Findings        map[string]string `json:"findings"`
EmailsFound     []string          `json:"emails_found"`
SubdomainsFound []string          `json:"subdomains_found"`
EmployeesFound  []string          `json:"employees_found"`
SocialProfiles  []string          `json:"social_profiles"`
BreachesFound   []string          `json:"breaches_found"`
GitHubLeaks     []string          `json:"github_leaks"`
RawCombined     string            `json:"raw"`
}

// RevEngPayload is the structured payload sent to /reveng for AI analysis.
type RevEngPayload struct {
Target            string            `json:"target"`
AnalysisMode      string            `json:"analysis_mode"`
FileType          string            `json:"file_type"`
Architecture      string            `json:"architecture"`
Bitness           string            `json:"bitness"`
Stripped          bool              `json:"stripped"`
PIE               bool              `json:"pie"`
NX                bool              `json:"nx"`
Canary            bool              `json:"canary"`
RELRO             string            `json:"relro"`
ToolsRun          []string          `json:"tools_run"`
Findings          map[string]string `json:"findings"`
VulnFunctions     []string          `json:"vuln_functions"`
YARAMatches       []string          `json:"yara_matches"`
ROPGadgets        []string          `json:"rop_gadgets"`
SuspiciousStrings []string          `json:"suspicious_strings"`
RawCombined       string            `json:"raw"`
}

// LocatePayload is the structured payload sent to /locate for AI analysis.
type LocatePayload struct {
Target      string            `json:"target"`
TargetType  string            `json:"target_type"`
ToolsRun    []string          `json:"tools_run"`
Findings    map[string]string `json:"findings"`
Coordinates []string          `json:"coordinates"`
City        string            `json:"city"`
Country     string            `json:"country"`
ISP         string            `json:"isp"`
ExifGPS     string            `json:"exif_gps"`
WiFiSSIDs   []string          `json:"wifi_ssids"`
CellTowers  []string          `json:"cell_towers"`
RawCombined string            `json:"raw"`
}

// SendOSINTDeep sends OSINT findings to backend AI for deep analysis.
// Falls back to /chat with structured prompt if dedicated endpoint not available.
func SendOSINTDeep(payload OSINTPayload) (string, error) {
result, err := post("/osint-deep", payload)
if err == nil {
return result, nil
}
// Fallback: use /chat with structured prompt
var sb strings.Builder
sb.WriteString("OSINT Deep Scan for: " + payload.Target + " (type: " + payload.TargetType + ")\n")
sb.WriteString("Tools: " + strings.Join(payload.ToolsRun, ", ") + "\n\n")
if len(payload.EmailsFound) > 0 {
n := len(payload.EmailsFound)
if n > 10 { n = 10 }
sb.WriteString("Emails: " + strings.Join(payload.EmailsFound[:n], ", ") + "\n")
}
if len(payload.SubdomainsFound) > 0 {
sb.WriteString(fmt.Sprintf("Subdomains: %d found\n", len(payload.SubdomainsFound)))
}
if len(payload.SocialProfiles) > 0 {
n := len(payload.SocialProfiles)
if n > 5 { n = 5 }
sb.WriteString("Social profiles:\n" + strings.Join(payload.SocialProfiles[:n], "\n") + "\n")
}
if len(payload.BreachesFound) > 0 {
n := len(payload.BreachesFound)
if n > 5 { n = 5 }
sb.WriteString("BREACHES FOUND:\n" + strings.Join(payload.BreachesFound[:n], "\n") + "\n")
}
if len(payload.EmployeesFound) > 0 {
sb.WriteString(fmt.Sprintf("Employees: %d found\n", len(payload.EmployeesFound)))
}
if len(payload.GitHubLeaks) > 0 {
sb.WriteString(fmt.Sprintf("GitHub leaks: %d\n", len(payload.GitHubLeaks)))
}
raw := payload.RawCombined
if len(raw) > 20000 { raw = raw[:20000] + "\n...[truncated]" }
if raw != "" { sb.WriteString("\nFindings:\n" + raw) }
sb.WriteString("\n\nProvide: 1) Digital footprint summary 2) Attack surface 3) Breach/credential risk 4) Social engineering vectors 5) Pentest next steps 6) MITRE ATT&CK mapping")
return post("/chat", chatRequest{Prompt: sb.String(), Messages: []Message{}})
}

// SendRevEng sends RE findings to backend AI for vulnerability analysis.
// Falls back to /chat with structured prompt if dedicated endpoint not available.
func SendRevEng(payload RevEngPayload) (string, error) {
result, err := post("/reveng", payload)
if err == nil {
return result, nil
}
var sb strings.Builder
sb.WriteString("Reverse Engineering Analysis for: " + payload.Target + "\n")
sb.WriteString(fmt.Sprintf("Mode: %s | File: %s | Arch: %s %s\n", payload.AnalysisMode, payload.FileType, payload.Architecture, payload.Bitness))
sb.WriteString(fmt.Sprintf("Security: PIE=%v NX=%v Canary=%v RELRO=%s Stripped=%v\n", payload.PIE, payload.NX, payload.Canary, payload.RELRO, payload.Stripped))
if len(payload.VulnFunctions) > 0 {
sb.WriteString("Vulnerable functions: " + strings.Join(payload.VulnFunctions, ", ") + "\n")
}
if len(payload.YARAMatches) > 0 {
sb.WriteString(fmt.Sprintf("YARA matches: %d\n", len(payload.YARAMatches)))
}
if len(payload.ROPGadgets) > 0 {
sb.WriteString(fmt.Sprintf("ROP gadgets: %d found\n", len(payload.ROPGadgets)))
}
if len(payload.SuspiciousStrings) > 0 {
n := len(payload.SuspiciousStrings)
if n > 10 { n = 10 }
sb.WriteString("Suspicious strings:\n" + strings.Join(payload.SuspiciousStrings[:n], "\n") + "\n")
}
sb.WriteString("Tools run: " + strings.Join(payload.ToolsRun, ", ") + "\n")
raw := payload.RawCombined
if len(raw) > 40000 { raw = raw[:40000] + "\n...[truncated]" }
if raw != "" { sb.WriteString("\nAnalysis output:\n" + raw) }
sb.WriteString("\n\nProvide: 1) Binary purpose/functionality 2) Vulnerabilities found (BOF, format string, UAF, etc.) 3) Exploit development approach (ROP chains, shellcode) 4) Malware indicators 5) CVEs for identified libraries 6) Decompiled function analysis")
return post("/chat", chatRequest{Prompt: sb.String(), Messages: []Message{}})
}

// SendLocate sends geolocation findings to backend AI for analysis.
// Falls back to /chat with structured prompt if dedicated endpoint not available.
func SendLocate(payload LocatePayload) (string, error) {
result, err := post("/locate", payload)
if err == nil {
return result, nil
}
var sb strings.Builder
sb.WriteString("Geolocation Analysis for: " + payload.Target + " (type: " + payload.TargetType + ")\n")
if payload.City != "" || payload.Country != "" {
sb.WriteString("Location: " + payload.City + ", " + payload.Country + "\n")
}
if payload.ISP != "" {
sb.WriteString("ISP/Org: " + payload.ISP + "\n")
}
if len(payload.Coordinates) > 0 {
sb.WriteString("GPS: " + strings.Join(payload.Coordinates, " | ") + "\n")
}
if payload.ExifGPS != "" {
sb.WriteString("EXIF GPS: " + payload.ExifGPS + "\n")
}
if len(payload.WiFiSSIDs) > 0 {
sb.WriteString(fmt.Sprintf("WiFi SSIDs: %d captured\n", len(payload.WiFiSSIDs)))
}
if len(payload.CellTowers) > 0 {
sb.WriteString(fmt.Sprintf("Cell towers: %d captured\n", len(payload.CellTowers)))
}
sb.WriteString("Tools: " + strings.Join(payload.ToolsRun, ", ") + "\n")
raw := payload.RawCombined
if len(raw) > 10000 { raw = raw[:10000] + "\n...[truncated]" }
if raw != "" { sb.WriteString("\nData:\n" + raw) }
sb.WriteString("\n\nProvide: 1) Physical location summary 2) Network infrastructure analysis 3) Attack surface from location data 4) Privacy exposure assessment 5) Recommended follow-up actions")
return post("/chat", chatRequest{Prompt: sb.String(), Messages: []Message{}})
}

// GetBaseURL returns the current best backend URL (exported for SSE streaming).
func GetBaseURL() string {
	return getBaseURL()
}

// GetAPIKeyExported returns the current API key (exported for SSE streaming).
func GetAPIKeyExported() string {
	return getAPIKey()
}

// SendDevSecAnalyze sends DevSec scan findings to the backend for AI analysis.
func SendDevSecAnalyze(target, findings string) (string, error) {
	return post("/api/devsec/analyze", map[string]string{
		"target":   target,
		"findings": findings,
	})
}

// SendChainAnalyze sends bug list to the backend for exploit chain analysis.
func SendChainAnalyze(target string, bugs []map[string]interface{}) (string, error) {
	return post("/api/chain/analyze", map[string]interface{}{
		"target": target,
		"bugs":   bugs,
	})
}

// SendRedTeamPhase sends a red team phase request to the backend.
func SendRedTeamPhase(company string, phase int, scope map[string]interface{}, priorSummaries []string) (string, error) {
	return post("/api/red-team/phase", map[string]interface{}{
		"company":         company,
		"phase":           phase,
		"scope":           scope,
		"prior_summaries": priorSummaries,
	})
}

// ─── Attack Session Tracking (for web dashboard real-time data) ───────────────

// AttackSessionPayload is sent to the backend to track attack sessions.
// The backend writes this to the attack_sessions Supabase table.
type AttackSessionPayload struct {
	Target        string  `json:"target"`
	Mode          string  `json:"mode"`           // omega|recon|hunt|abhimanyu|chain|vibe-hack
	Status        string  `json:"status"`         // running|completed|failed
	BugsFound     int     `json:"bugs_found"`
	ToolsRan      int     `json:"tools_ran"`
	FindingChance int     `json:"finding_chance"` // 0-100
	StartedAt     string  `json:"started_at"`     // RFC3339
	CompletedAt   string  `json:"completed_at,omitempty"`
}

// SendAttackSessionStart notifies the backend that an attack session has started.
// Non-blocking — runs in background goroutine. Never fails the caller.
func SendAttackSessionStart(target, mode string) {
	go func() {
		payload := AttackSessionPayload{
			Target:    target,
			Mode:      mode,
			Status:    "running",
			StartedAt: time.Now().UTC().Format(time.RFC3339),
		}
		// Fire-and-forget — ignore errors
		_, _ = post("/api/attack-session/start", payload)
	}()
}

// SendAttackSessionComplete notifies the backend that an attack session has completed.
// Non-blocking — runs in background goroutine. Never fails the caller.
func SendAttackSessionComplete(target, mode string, bugsFound, toolsRan, findingChance int) {
	go func() {
		payload := AttackSessionPayload{
			Target:        target,
			Mode:          mode,
			Status:        "completed",
			BugsFound:     bugsFound,
			ToolsRan:      toolsRan,
			FindingChance: findingChance,
			StartedAt:     time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), // approximate
			CompletedAt:   time.Now().UTC().Format(time.RFC3339),
		}
		// Fire-and-forget — ignore errors
		_, _ = post("/api/attack-session/complete", payload)
	}()
}
