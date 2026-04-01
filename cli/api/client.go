package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const backendURL = "http://localhost:3000/chat"

type promptRequest struct {
	Prompt string `json:"prompt"`
}

type promptResponse struct {
	Message string `json:"message"`
}

// SendPrompt sends a prompt to the CyberMind backend and returns the response.
func SendPrompt(prompt string) (string, error) {
	payload, err := json.Marshal(promptRequest{Prompt: prompt})
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := http.Post(backendURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to reach backend: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result promptResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return string(body), nil
	}

	return result.Message, nil
}
