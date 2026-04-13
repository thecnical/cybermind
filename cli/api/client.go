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

// SSRF protection — reject private/loopback IPs in CYBERMIND_API env var
func getBaseURL() string {
	if raw := os.Getenv("CYBERMIND_API"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return defaultBackendURL
		}
		// Block SSRF: reject private/loopback/link-local hostnames
		host := u.Hostname()
		if isSSRFHost(host) {
			return defaultBackendURL
		}
		return strings.TrimRight(raw, "/")
	}
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
	Action   string `json:"action"` // migration/upgrade message
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
// Handles Render cold start transparently — shows progress, auto-retries.
func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	// Attempt 1 — try immediately
	result, err := doPost(endpoint, payload)
	if err == nil {
		return result, nil
	}

	// Not a backend-down error — return immediately (auth error, etc.)
	if !isBackendDown(err) {
		return "", err
	}

	// Backend is sleeping — wake it up with progress display
	fmt.Print("\r  ⟳ Backend waking up ")
	wakeStart := time.Now()
	maxWake := 90 * time.Second

	woke := false
	for time.Since(wakeStart) < maxWake {
		elapsed := int(time.Since(wakeStart).Seconds())
		dots := strings.Repeat(".", (elapsed/3)%4)
		spaces := strings.Repeat(" ", 3-(elapsed/3)%4)
		fmt.Printf("\r  ⟳ Backend waking up%s%s (%ds)", dots, spaces, elapsed)

		resp, pingErr := fastClient.Get(getBaseURL() + "/ping")
		if pingErr == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				woke = true
				break
			}
		}
		time.Sleep(3 * time.Second)
	}

	if !woke {
		fmt.Println()
		return "", fmt.Errorf("backend took too long to start. Try again in 30 seconds")
	}

	// Backend is up — small buffer then retry
	time.Sleep(1 * time.Second)
	fmt.Printf("\r  ✓ Backend ready — sending request...%s\n", strings.Repeat(" ", 20))

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

// doPost performs a single HTTP POST and parses the JSON response.
func doPost(endpoint string, payload []byte) (string, error) {
	req, err := http.NewRequest("POST", getBaseURL()+endpoint, bytes.NewBuffer(payload))
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

// SendChat sends prompt with conversation history
func SendChat(prompt string, history []Message) (string, error) {
	return post("/chat", chatRequest{Prompt: prompt, Messages: history})
}

// SendChatStream sends prompt and streams tokens via SSE.
// onToken is called for each received token. Returns full response when done.
// Falls back to regular /chat if streaming fails.
func SendChatStream(prompt string, history []Message, onToken func(string)) (string, error) {
	payload, err := json.Marshal(chatRequest{Prompt: prompt, Messages: history})
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
