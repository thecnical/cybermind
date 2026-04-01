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

// Default to live Render URL; override with CYBERMIND_API env var for local dev
const defaultBackendURL = "https://cybermind-api.onrender.com/chat"

func getBackendURL() string {
	if url := os.Getenv("CYBERMIND_API"); url != "" {
		return url
	}
	return defaultBackendURL
}

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

// SendPrompt sends a prompt to the CyberMind backend and returns the AI response.
func SendPrompt(prompt string) (string, error) {
	payload, err := json.Marshal(promptRequest{Prompt: prompt})
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	client := &http.Client{Timeout: 120 * time.Second}

	resp, err := client.Post(getBackendURL(), "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", errors.New("backend is unreachable — check your connection or run locally")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result promptResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid response from backend: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}

	return result.Response, nil
}
