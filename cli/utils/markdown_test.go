package utils

import (
	"strings"
	"testing"
	"testing/quick"
)

func TestStripMarkdown_Heading3(t *testing.T) {
	got := StripMarkdown("### Heading")
	if !strings.Contains(got, "HEADING") {
		t.Errorf("expected HEADING in output, got %q", got)
	}
	if strings.Contains(got, "#") {
		t.Errorf("expected no # markers in output, got %q", got)
	}
}

func TestStripMarkdown_Bold(t *testing.T) {
	got := StripMarkdown("**bold**")
	if got != "bold" {
		t.Errorf("expected 'bold', got %q", got)
	}
}

func TestStripMarkdown_InlineCode(t *testing.T) {
	got := StripMarkdown("`code`")
	if got != "code" {
		t.Errorf("expected 'code', got %q", got)
	}
}

func TestStripMarkdown_FencedBlock(t *testing.T) {
	input := "```\nline1\nline2\n```"
	got := StripMarkdown(input)
	if !strings.Contains(got, "    line1") {
		t.Errorf("expected 4-space indented line1, got %q", got)
	}
	if !strings.Contains(got, "    line2") {
		t.Errorf("expected 4-space indented line2, got %q", got)
	}
}

func TestStripMarkdown_BulletDash(t *testing.T) {
	got := StripMarkdown("- item")
	if got != "  • item" {
		t.Errorf("expected '  • item', got %q", got)
	}
}

func TestStripMarkdown_NumberedListPreserved(t *testing.T) {
	got := StripMarkdown("1. first item")
	if got != "1. first item" {
		t.Errorf("expected numbered list preserved, got %q", got)
	}
}

func TestStripMarkdown_EmptyString(t *testing.T) {
	got := StripMarkdown("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestStripMarkdown_NoMarkers(t *testing.T) {
	input := "### Title\n**bold** and `code` here\n- bullet"
	got := StripMarkdown(input)
	if strings.Contains(got, "#") {
		t.Errorf("output contains # markers: %q", got)
	}
	if strings.Contains(got, "**") {
		t.Errorf("output contains ** markers: %q", got)
	}
	if strings.Contains(got, "`") {
		t.Errorf("output contains backtick markers: %q", got)
	}
}

// TestStripMarkdownIdempotency validates Property 8:
// StripMarkdown(StripMarkdown(s)) == StripMarkdown(s) for any string s
//
// Validates: Requirements 11.8
func TestStripMarkdownIdempotency(t *testing.T) {
	f := func(s string) bool {
		// Skip strings with null bytes
		if strings.ContainsRune(s, 0) {
			return true
		}
		once := StripMarkdown(s)
		twice := StripMarkdown(once)
		return once == twice
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestStripMarkdownLengthInvariant validates Property 7:
// len(StripMarkdown(s)) <= len(s) + lines*4 + 4 for any string s
// (bullet conversion adds "  • " (4 bytes) while removing "- " (2 bytes),
// so output can be slightly longer per line)
//
// Validates: Requirements 11.7
func TestStripMarkdownLengthInvariant(t *testing.T) {
	f := func(s string) bool {
		if strings.ContainsRune(s, 0) {
			return true
		}
		lineCount := strings.Count(s, "\n")
		return len(StripMarkdown(s)) <= len(s)+lineCount*4+4
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestStripMarkdownMarkerRemoval validates Property 6:
// Output contains no # heading markers, ** bold markers, or backtick markers
//
// Validates: Requirements 11.1, 11.2, 11.3, 11.9
func TestStripMarkdownMarkerRemoval(t *testing.T) {
	f := func(s string) bool {
		if strings.ContainsRune(s, 0) {
			return true
		}
		out := StripMarkdown(s)
		// No heading markers at start of line
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				return false
			}
		}
		// No bold markers
		if strings.Contains(out, "**") {
			return false
		}
		// No backtick markers (inline code)
		if strings.Contains(out, "`") {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
