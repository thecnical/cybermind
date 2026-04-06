package main

import (
	"testing"
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
