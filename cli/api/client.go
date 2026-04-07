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

var httpClient = &http.Client{Timeout: 200 * time.Second} // 200s — backend AI timeout is 180s

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

// WakeUp pings /health to wake Render from sleep
func WakeUp() bool {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(getBaseURL() + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
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

func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := httpClient.Post(getBaseURL()+endpoint, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("cannot reach CyberMind backend — check your internet connection")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result promptResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("unexpected response from backend: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	// Return analysis if present, otherwise response
	if result.Analysis != "" {
		return result.Analysis, nil
	}
	return result.Response, nil
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

// SendToolHelp — tool usage guide
func SendToolHelp(tool, task string) (string, error) {
	return post("/tools/help", map[string]string{"tool": tool, "task": task})
}
