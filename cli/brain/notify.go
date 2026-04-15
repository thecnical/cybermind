// Package brain - Telegram notification system for CyberMind
package brain

import (
"bytes"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"path/filepath"
"time"
)

// NotifyConfig holds Telegram bot configuration
type NotifyConfig struct {
TelegramBotToken string `json:"telegram_bot_token"`
TelegramChatID   string `json:"telegram_chat_id"`
SlackWebhook     string `json:"slack_webhook"`
Enabled          bool   `json:"enabled"`
}

func notifyConfigFile() string {
home, _ := os.UserHomeDir()
return filepath.Join(home, ".cybermind", "notify_config.json")
}

// LoadNotifyConfig loads notification config from disk.
func LoadNotifyConfig() *NotifyConfig {
data, err := os.ReadFile(notifyConfigFile())
if err != nil {
return &NotifyConfig{}
}
var cfg NotifyConfig
if err := json.Unmarshal(data, &cfg); err != nil {
return &NotifyConfig{}
}
return &cfg
}

// SaveNotifyConfig saves notification config to disk.
func SaveNotifyConfig(cfg *NotifyConfig) error {
home, _ := os.UserHomeDir()
dir := filepath.Join(home, ".cybermind")
if err := os.MkdirAll(dir, 0700); err != nil {
return err
}
data, err := json.MarshalIndent(cfg, "", "  ")
if err != nil {
return err
}
return os.WriteFile(notifyConfigFile(), data, 0600)
}

// SendTelegram sends a message to Telegram.
func SendTelegram(token, chatID, message string) error {
if token == "" || chatID == "" {
return fmt.Errorf("telegram not configured")
}
payload := map[string]interface{}{
"chat_id":    chatID,
"text":       message,
"parse_mode": "Markdown",
}
body, err := json.Marshal(payload)
if err != nil {
return err
}
req, err := http.NewRequest("POST",
fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token),
bytes.NewBuffer(body))
if err != nil {
return err
}
req.Header.Set("Content-Type", "application/json")
client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Do(req)
if err != nil {
return err
}
defer resp.Body.Close()
io.ReadAll(io.LimitReader(resp.Body, 4096))
return nil
}

// NotifyBugFound sends a Telegram alert when a bug is found.
func NotifyBugFound(target, bugTitle, severity, url, reportPath string) {
cfg := LoadNotifyConfig()
if !cfg.Enabled || cfg.TelegramBotToken == "" {
// Also check env vars
cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")
if cfg.TelegramBotToken == "" {
return
}
}
emoji := "🟡"
switch severity {
case "critical":
emoji = "🔴"
case "high":
emoji = "🟠"
case "medium":
emoji = "🟡"
}
msg := fmt.Sprintf("%s *Bug Found on %s*\n\n*%s* [%s]\n\nURL: `%s`\nReport: `%s`",
emoji, target, bugTitle, severity, url, reportPath)
SendTelegram(cfg.TelegramBotToken, cfg.TelegramChatID, msg)
}

// NotifyScanComplete sends a Telegram alert when a scan completes.
func NotifyScanComplete(target string, bugsFound int, duration time.Duration) {
cfg := LoadNotifyConfig()
token := cfg.TelegramBotToken
chatID := cfg.TelegramChatID
if token == "" {
token = os.Getenv("TELEGRAM_BOT_TOKEN")
chatID = os.Getenv("TELEGRAM_CHAT_ID")
}
if token == "" {
return
}
emoji := "✅"
if bugsFound > 0 {
emoji = "🎯"
}
msg := fmt.Sprintf("%s *Scan Complete: %s*\n\nBugs found: *%d*\nDuration: %s",
emoji, target, bugsFound, duration.Round(time.Second))
SendTelegram(token, chatID, msg)
}
