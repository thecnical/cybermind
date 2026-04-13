package vibecoder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// APIMessage is a simple role/content pair for the /chat endpoint.
type APIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// SendVibeChat sends a prompt to the CyberMind /chat endpoint with streaming.
// onToken is called for each streamed token. Falls back to non-streaming if needed.
// This is used as a fallback when the full vibe backend isn't wired.
func SendVibeChat(prompt string, history []APIMessage, onToken func(string)) (string, error) {
	msgs := make([]chatMsg, 0, len(history))
	for _, h := range history {
		msgs = append(msgs, chatMsg{Role: h.Role, Content: h.Content})
	}
	return sendVibeChatInternal(prompt, msgs, onToken)
}

func sendVibeChatInternal(prompt string, history []chatMsg, onToken func(string)) (string, error) {
	backendURL := os.Getenv("CYBERMIND_API")
	if backendURL == "" {
		backendURL = "https://cybermind-backend-8yrt.onrender.com"
	}
	backendURL = strings.TrimRight(backendURL, "/")

	// Get API key
	apiKey := os.Getenv("CYBERMIND_KEY")
	if apiKey == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(home + "/.cybermind/config.json"); err == nil {
				var cfg struct{ Key string `json:"key"` }
				if json.Unmarshal(data, &cfg) == nil {
					apiKey = cfg.Key
				}
			}
		}
	}

	body := map[string]interface{}{
		"prompt":   prompt,
		"messages": history,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	// Try streaming first via /api/vibe/chat/stream
	streamReq, err := http.NewRequest("POST", backendURL+"/api/vibe/chat/stream", bytes.NewReader(payload))
	if err == nil {
		streamReq.Header.Set("Content-Type", "application/json")
		streamReq.Header.Set("Accept", "text/event-stream")
		if apiKey != "" {
			streamReq.Header.Set("X-API-Key", apiKey)
		}

		client := &http.Client{Timeout: 180 * time.Second}
		resp, err := client.Do(streamReq)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var full strings.Builder
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
				if json.Unmarshal([]byte(data), &event) == nil {
					if event.Error != "" {
						return "", fmt.Errorf("%s", event.Error)
					}
					if event.Done {
						break
					}
					if event.Token != "" {
						full.WriteString(event.Token)
						if onToken != nil {
							onToken(event.Token)
						}
					}
				}
			}
			result := full.String()
			if result != "" {
				return result, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback: /chat endpoint (non-streaming)
	chatReq, err := http.NewRequest("POST", backendURL+"/chat", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	chatReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		chatReq.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(chatReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	var result struct {
		Success  bool   `json:"success"`
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}

	// Stream the response token by token for consistent UX
	if onToken != nil {
		words := strings.Fields(result.Response)
		for _, w := range words {
			onToken(w + " ")
		}
	}
	return result.Response, nil
}
