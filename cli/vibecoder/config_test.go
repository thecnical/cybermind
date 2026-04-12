package vibecoder

import (
	"strings"
	"testing"
)

// Property 10: API Key Masking — table-driven (gopter not yet in module)
// Feature: cybermind-vibe-coder
// Validates: Requirements 8.3, 10.4
//
// For any non-empty API key string, MaskAPIKey must:
//  1. Never return the full key
//  2. Always show exactly the last 4 characters
//  3. Prefix with "****"
func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		wantResult  string
		wantNotFull bool // result must not equal the original key
	}{
		{
			name:       "empty key returns (not set)",
			key:        "",
			wantResult: "(not set)",
		},
		{
			name:        "4-char key: all chars shown after ****",
			key:         "abcd",
			wantResult:  "****abcd",
			wantNotFull: true,
		},
		{
			name:        "3-char key: all chars shown after ****",
			key:         "abc",
			wantResult:  "****abc",
			wantNotFull: true,
		},
		{
			name:        "long key: only last 4 chars shown",
			key:         "sk-supersecretkey1234",
			wantResult:  "****1234",
			wantNotFull: true,
		},
		{
			name:        "exactly 5 chars: last 4 shown",
			key:         "12345",
			wantResult:  "****2345",
			wantNotFull: true,
		},
		{
			name:        "unicode key: last 4 runes shown",
			key:         "αβγδεζ",
			wantResult:  "****γδεζ",
			wantNotFull: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskAPIKey(tc.key)

			// Check exact result
			if got != tc.wantResult {
				t.Errorf("MaskAPIKey(%q) = %q, want %q", tc.key, got, tc.wantResult)
			}

			if tc.key == "" {
				return
			}

			// Property 1: never return the full key
			if tc.wantNotFull && got == tc.key {
				t.Errorf("MaskAPIKey(%q) returned full key", tc.key)
			}

			// Property 2: always prefixed with "****"
			if !strings.HasPrefix(got, "****") {
				t.Errorf("MaskAPIKey(%q) = %q, missing **** prefix", tc.key, got)
			}

			// Property 3: last 4 runes of key appear at end of result
			runes := []rune(tc.key)
			last4 := string(runes[max4(0, len(runes)-4):])
			if !strings.HasSuffix(got, last4) {
				t.Errorf("MaskAPIKey(%q) = %q, want suffix %q", tc.key, got, last4)
			}
		})
	}
}

func max4(a, b int) int {
	if a > b {
		return a
	}
	return b
}
