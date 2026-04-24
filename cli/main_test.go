package main

import (
	"strings"
	"testing"
	"testing/quick"
)

func TestParseToolsFlag_NoFlag(t *testing.T) {
	target, tools, err := parseToolsFlag([]string{"example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com" {
		t.Errorf("expected target=example.com, got %q", target)
	}
	if tools != nil {
		t.Errorf("expected tools=nil, got %v", tools)
	}
}

func TestParseToolsFlag_WithTools(t *testing.T) {
	target, tools, err := parseToolsFlag([]string{"example.com", "--tools", "nmap,httpx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target != "example.com" {
		t.Errorf("expected target=example.com, got %q", target)
	}
	if len(tools) != 2 || tools[0] != "nmap" || tools[1] != "httpx" {
		t.Errorf("expected [nmap httpx], got %v", tools)
	}
}

func TestParseToolsFlag_UnknownTool(t *testing.T) {
	_, _, err := parseToolsFlag([]string{"example.com", "--tools", "nmap,unknowntool"})
	if err == nil {
		t.Error("expected error for unknown tool, got nil")
	}
}

// Feature: cybermind-new-modes, Property 11: Input Sanitization Completeness
// For any target string passed to sanitizeTarget, the returned string SHALL
// contain only characters in the set [a-zA-Z0-9._:\-\[\]] and SHALL never
// contain shell metacharacters.
// Validates: Requirements 15.1, 15.5
func TestProperty11_InputSanitizationCompleteness(t *testing.T) {
	// Test that sanitizeTarget only allows safe characters
	shellMetachars := []string{";", "&", "|", "$", "(", ")", "{", "}", "<", ">", "`", "'", "\"", "\n", "\t"}

	for _, meta := range shellMetachars {
		input := "example.com" + meta + "evil"
		result := sanitizeTarget(input)
		if strings.Contains(result, meta) {
			t.Errorf("sanitizeTarget(%q) contains metachar %q: %q", input, meta, result)
		}
	}

	// Property: output only contains allowed chars
	f := func(s string) bool {
		result := sanitizeTarget(s)
		for _, r := range result {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '.' || r == '-' || r == ':' || r == '[' || r == ']') {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
