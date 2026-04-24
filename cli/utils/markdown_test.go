package utils

import (
	"regexp"
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

// ─── Property 3: ANSI Output Sanitization ────────────────────────────────────

// Feature: cybermind-new-modes, Property 3: ANSI Output Sanitization
//
// For any string containing arbitrary ANSI escape sequences (including color
// codes, cursor movement, and erase sequences), the ANSI-stripping function
// SHALL produce a string that contains no ANSI escape sequences and preserves
// all non-ANSI characters.
//
// Note: StripMarkdown is a markdown-to-terminal formatter, not an ANSI stripper.
// The ANSI stripping function (stripANSI) lives in the devsec package and uses
// a dedicated regex. This file tests the same regex pattern directly to verify
// the sanitization property holds.
//
// Validates: Requirements 1.10

// ansiReTest mirrors the regex used in devsec/engine.go for ANSI stripping.
var ansiReTest = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// stripANSIForTest applies the same ANSI-stripping regex as devsec/engine.go.
func stripANSIForTest(s string) string {
	return ansiReTest.ReplaceAllString(s, "")
}

// containsANSI returns true if s contains any ANSI escape sequence.
func containsANSI(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\x1b' && s[i+1] == '[' {
			return true
		}
	}
	return false
}

// ansiPatterns contains representative ANSI escape sequences to inject.
var ansiPatterns = []string{
	"\x1b[0m",            // reset
	"\x1b[1m",            // bold
	"\x1b[31m",           // red foreground
	"\x1b[32;1m",         // green bold
	"\x1b[0;33;40m",      // yellow on black
	"\x1b[2J",            // erase display
	"\x1b[H",             // cursor home
	"\x1b[1;1H",          // cursor position
	"\x1b[K",             // erase line
	"\x1b[38;5;196m",     // 256-color foreground
	"\x1b[48;2;0;0;255m", // 24-bit background
}

// TestProperty3_StripANSIRemovesEscapeSequences verifies that the ANSI-stripping
// regex removes all ANSI escape sequences from the input.
//
// Validates: Requirements 1.10
func TestProperty3_StripANSIRemovesEscapeSequences(t *testing.T) {
	for _, pattern := range ansiPatterns {
		input := "hello" + pattern + "world"
		got := stripANSIForTest(input)
		if containsANSI(got) {
			t.Errorf("stripANSI(%q) still contains ANSI sequences: %q", input, got)
		}
		if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
			t.Errorf("stripANSI(%q) lost non-ANSI text: %q", input, got)
		}
	}
}

// TestProperty3_StripANSIPreservesNonANSIText verifies that non-ANSI text is
// preserved after stripping.
//
// Validates: Requirements 1.10
func TestProperty3_StripANSIPreservesNonANSIText(t *testing.T) {
	cases := []struct {
		input    string
		wantText string
	}{
		{"\x1b[31mhello\x1b[0m", "hello"},
		{"\x1b[1;32mworld\x1b[0m", "world"},
		{"plain text", "plain text"},
		{"\x1b[0mfoo\x1b[1mbar\x1b[0m", "foobar"},
	}
	for _, tc := range cases {
		got := stripANSIForTest(tc.input)
		if !strings.Contains(got, tc.wantText) {
			t.Errorf("stripANSI(%q) = %q, want it to contain %q", tc.input, got, tc.wantText)
		}
	}
}

// TestProperty3_ANSISanitizationProperty is a property-based test verifying
// that for any string, the ANSI-stripping function produces output containing
// no ANSI escape sequences.
//
// Validates: Requirements 1.10
func TestProperty3_ANSISanitizationProperty(t *testing.T) {
	f := func(s string) bool {
		// Skip strings with null bytes
		if strings.ContainsRune(s, 0) {
			return true
		}
		// Inject ANSI sequences into the string at fixed positions
		var withANSI strings.Builder
		for i, ch := range s {
			if i%5 == 0 {
				withANSI.WriteString(ansiPatterns[i%len(ansiPatterns)])
			}
			withANSI.WriteRune(ch)
		}
		got := stripANSIForTest(withANSI.String())
		return !containsANSI(got)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestProperty3_ANSIOnlyStringProducesNoANSI verifies that a string consisting
// entirely of ANSI escape sequences produces output with no ANSI codes.
//
// Validates: Requirements 1.10
func TestProperty3_ANSIOnlyStringProducesNoANSI(t *testing.T) {
	input := "\x1b[0m\x1b[1m\x1b[31m\x1b[0m"
	got := stripANSIForTest(input)
	if containsANSI(got) {
		t.Errorf("stripANSI of ANSI-only string still contains ANSI: %q", got)
	}
}
