package storage

import (
	"fmt"
	"time"
)

// Entry represents a single chat exchange
type Entry struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	AI        string `json:"ai"`
}

// in-memory cache
var entries []Entry

// Load reads history from disk into memory. Call once on startup.
func Load() error {
	loaded, err := ReadFromFile()
	if err != nil {
		return err
	}
	entries = loaded
	return nil
}

// AddEntry appends a new chat exchange and persists to disk
func AddEntry(userInput, aiResponse string) error {
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		User:      userInput,
		AI:        aiResponse,
	}
	entries = append(entries, entry)
	return SaveToFile(entries)
}

// GetHistory returns all stored entries
func GetHistory() []Entry {
	return entries
}

// ClearHistory wipes memory and disk
func ClearHistory() error {
	entries = []Entry{}
	return SaveToFile(entries)
}

// PrintHistory formats and prints history to stdout
func PrintHistory() {
	if len(entries) == 0 {
		fmt.Println("  No chat history found.")
		return
	}
	fmt.Println("\n  📜 Chat History")
	fmt.Println("  " + repeat("─", 60))
	for i, e := range entries {
		fmt.Printf("  [%d] %s\n", i+1, e.Timestamp)
		fmt.Printf("  User: %s\n", e.User)
		fmt.Printf("  AI:   %s\n", truncate(e.AI, 120))
		fmt.Println("  " + repeat("─", 60))
	}
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
