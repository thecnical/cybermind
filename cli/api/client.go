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

var httpClient = &http.Client{Timeout: 120 * time.Second}

// Message represents a single chat message for conversation history
type Message struct {
	Role    string `json:"role"`    // "user" or "assistant"
	Content string `json:"content"`
}

// chatRequest includes prompt + full conversation history
type chatRequest struct {
	Prompt   string    `json:"prompt"`
	Messages []Message `json:"messages"`
}

type promptResponse struct {
	Success  bool   `json:"success"`
	Response string `json:"response"`
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

func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := httpClient.Post(getBaseURL()+endpoint, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf(
			"cannot reach CyberMind backend — check your internet connection",
		)
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
	return result.Response, nil
}

// SendChat sends prompt with full conversation history for memory
func SendChat(prompt string, history []Message) (string, error) {
	return post("/chat", chatRequest{
		Prompt:   prompt,
		Messages: history,
	})
}

// SendPrompt — simple chat without history (used by command mode)
func SendPrompt(prompt string) (string, error) {
	return post("/chat", chatRequest{Prompt: prompt, Messages: []Message{}})
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
