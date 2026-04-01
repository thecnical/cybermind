package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const defaultBackendURL = "https://cybermind-backend.onrender.com"

func getBaseURL() string {
	if url := os.Getenv("CYBERMIND_API"); url != "" {
		return url
	}
	return defaultBackendURL
}

var httpClient = &http.Client{Timeout: 120 * time.Second}

type promptRequest struct {
	Prompt string `json:"prompt"`
}

type promptResponse struct {
	Success  bool   `json:"success"`
	Response string `json:"response"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Time     string `json:"time"`
	Error    string `json:"error"`
}

func post(endpoint string, body interface{}) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode error: %w", err)
	}

	resp, err := httpClient.Post(getBaseURL()+endpoint, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", errors.New("backend unreachable — start with: node src/app.js")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}

	var result promptResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.Response, nil
}

// SendPrompt — general AI chat
func SendPrompt(prompt string) (string, error) {
	return post("/chat", promptRequest{Prompt: prompt})
}

// SendScan — AI-guided scan for a target
func SendScan(target, scanType string) (string, error) {
	return post("/scan", map[string]string{"target": target, "type": scanType})
}

// SendRecon — AI-guided recon for a target
func SendRecon(target, reconType string) (string, error) {
	return post("/recon", map[string]string{"target": target, "type": reconType})
}

// SendExploit — AI-guided exploitation
func SendExploit(vulnerability, target string) (string, error) {
	return post("/exploit", map[string]string{"vulnerability": vulnerability, "target": target})
}

// SendPayload — msfvenom payload generation guide
func SendPayload(os_, arch, lhost, lport, format string) (string, error) {
	return post("/exploit/payload", map[string]string{
		"os": os_, "arch": arch, "lhost": lhost, "lport": lport, "format": format,
	})
}

// SendToolHelp — get help for a specific Kali tool
func SendToolHelp(tool, task string) (string, error) {
	return post("/tools/help", map[string]string{"tool": tool, "task": task})
}
