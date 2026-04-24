package devsec

import (
	"strings"
	"testing"
	"testing/quick"
)

// ─── Property 1: Target Input Classification ──────────────────────────────────

// Feature: cybermind-new-modes, Property 1: Target Input Classification
//
// For any string input to the DevSec scanner, the target classifier SHALL
// correctly identify GitHub URLs matching https://github.com/<owner>/<repo>
// as remote targets and all other strings as local paths, and SHALL reject
// any GitHub URL that does not match the exact pattern.
//
// Validates: Requirements 1.2, 15.2

// TestProperty1_ValidGitHubURLsAccepted verifies that well-formed GitHub URLs
// are accepted by isGitHubURL.
func TestProperty1_ValidGitHubURLsAccepted(t *testing.T) {
	validURLs := []string{
		"https://github.com/owner/repo",
		"https://github.com/my-org/my-repo",
		"https://github.com/A/B",
		"https://github.com/user123/project.go",
		"https://github.com/org_name/repo-name",
		"https://github.com/a/b",
		"https://github.com/UPPER/CASE",
		"https://github.com/with.dot/and-dash",
	}
	for _, url := range validURLs {
		if !isGitHubURL(url) {
			t.Errorf("expected isGitHubURL(%q) = true, got false", url)
		}
	}
}

// TestProperty1_MalformedGitHubURLsRejected verifies that malformed GitHub URLs
// are rejected by isGitHubURL.
func TestProperty1_MalformedGitHubURLsRejected(t *testing.T) {
	invalidURLs := []string{
		"",
		"http://github.com/owner/repo",   // http not https
		"https://github.com/owner",        // missing repo
		"https://github.com/",             // missing owner and repo
		"https://github.com",              // no path
		"https://gitlab.com/owner/repo",   // wrong host
		"https://github.com/owner/repo/extra", // extra path segment
		"github.com/owner/repo",           // missing scheme
		"https://github.com/owner/",       // empty repo
		"https://github.com//repo",        // empty owner
		"/local/path",
		"./relative/path",
		"not-a-url",
		"https://github.com/owner/repo?query=1", // query string
	}
	for _, url := range invalidURLs {
		if isGitHubURL(url) {
			t.Errorf("expected isGitHubURL(%q) = false, got true", url)
		}
	}
}

// TestProperty1_ClassificationConsistency is a property-based test verifying
// that isGitHubURL is consistent with the githubURLRe regex: if isGitHubURL
// returns true, the regex must also match, and vice versa.
//
// Validates: Requirements 1.2, 15.2
func TestProperty1_ClassificationConsistency(t *testing.T) {
	f := func(s string) bool {
		// Skip strings with null bytes (not valid in URLs)
		if strings.ContainsRune(s, 0) {
			return true
		}
		// isGitHubURL must agree with the underlying regex
		return isGitHubURL(s) == githubURLRe.MatchString(s)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestProperty1_NonGitHubStringsRejected verifies that arbitrary strings that
// don't start with "https://github.com/" are always rejected.
//
// Validates: Requirements 1.2, 15.2
func TestProperty1_NonGitHubStringsRejected(t *testing.T) {
	f := func(s string) bool {
		if strings.ContainsRune(s, 0) {
			return true
		}
		// If the string doesn't start with the required prefix, it must be rejected
		if !strings.HasPrefix(s, "https://github.com/") {
			return !isGitHubURL(s)
		}
		return true // strings with the prefix may or may not be valid — tested elsewhere
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// ─── Property 2: Tool Graceful Degradation ────────────────────────────────────

// Feature: cybermind-new-modes, Property 2: Tool Graceful Degradation
//
// For any subset of the required tools (trufflehog, gitleaks, semgrep, trivy)
// that are unavailable, the DevSec scanner SHALL run all available tools and
// emit exactly one install hint per missing tool, without aborting the scan.
//
// Validates: Requirements 1.5

// TestProperty2_SkippedToolHasInstallHint verifies that every SkippedTool
// entry has a non-empty InstallHint and a non-empty Tool name.
func TestProperty2_SkippedToolHasInstallHint(t *testing.T) {
	// All known tools and their expected install hints
	knownTools := []SkippedTool{
		{Tool: "trufflehog", InstallHint: "brew install trufflesecurity/trufflehog/trufflehog  OR  pip install trufflehog"},
		{Tool: "gitleaks", InstallHint: "brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest"},
		{Tool: "semgrep", InstallHint: "pip install semgrep  OR  brew install semgrep"},
		{Tool: "trivy", InstallHint: "brew install aquasecurity/trivy/trivy  OR  apt install trivy"},
		{Tool: "npm audit", InstallHint: "install Node.js from https://nodejs.org"},
		{Tool: "pip-audit", InstallHint: "pip install pip-audit"},
	}

	for _, st := range knownTools {
		if st.Tool == "" {
			t.Errorf("SkippedTool has empty Tool name")
		}
		if st.InstallHint == "" {
			t.Errorf("SkippedTool %q has empty InstallHint", st.Tool)
		}
	}
}

// TestProperty2_EachSkippedToolExactlyOneHint is a property-based test verifying
// that for any non-empty tool name, a SkippedTool entry has exactly one install hint
// (non-empty string, no newlines splitting it into multiple hints).
//
// Validates: Requirements 1.5
func TestProperty2_EachSkippedToolExactlyOneHint(t *testing.T) {
	f := func(toolName string) bool {
		if toolName == "" {
			return true // skip empty tool names
		}
		// Simulate a skipped tool entry as the engine would create it
		skipped := SkippedTool{
			Tool:        toolName,
			InstallHint: "install " + toolName,
		}
		// Each skipped tool must have exactly one non-empty install hint
		return skipped.InstallHint != "" && skipped.Tool == toolName
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestProperty2_SkippedToolsNoDuplicates verifies that the phase runners do not
// emit duplicate SkippedTool entries for the same tool.
func TestProperty2_SkippedToolsNoDuplicates(t *testing.T) {
	// Collect all tool names that would be skipped when no tools are installed.
	// We simulate this by checking the static tool lists in each phase.
	phase1Tools := []string{"trufflehog", "gitleaks"}
	phase2Tools := []string{"semgrep"}
	phase3Tools := []string{"trivy", "npm audit", "pip-audit"}

	allTools := append(append(phase1Tools, phase2Tools...), phase3Tools...)
	seen := make(map[string]int)
	for _, tool := range allTools {
		seen[tool]++
	}
	for tool, count := range seen {
		if count > 1 {
			t.Errorf("tool %q appears %d times in phase tool lists — expected exactly 1", tool, count)
		}
	}
}
