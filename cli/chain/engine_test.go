package chain

import (
	"strings"
	"testing"
	"time"

	"cybermind-cli/brain"
)

// ─── Bug List Extraction Tests ────────────────────────────────────────────────
// Validates: Requirements 5.3

// TestExtractBugs_EmptySlice verifies that extractBugs returns an empty slice
// when given no bugs.
func TestExtractBugs_EmptySlice(t *testing.T) {
	result := extractBugs([]brain.Bug{})
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(result))
	}
}

// TestExtractBugs_SingleBug verifies that a single bug is correctly converted
// to a map with all required fields.
func TestExtractBugs_SingleBug(t *testing.T) {
	bugs := []brain.Bug{
		{
			ID:       "xss_001",
			Title:    "Reflected XSS in search",
			Type:     "xss",
			URL:      "https://example.com/search?q=<script>",
			Severity: "high",
			Evidence: "alert(1) executed",
			PoC:      "1. Navigate to /search?q=<script>alert(1)</script>",
			Tool:     "dalfox",
			Verified: true,
		},
	}

	result := extractBugs(bugs)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	entry := result[0]
	checkField(t, entry, "id", "xss_001")
	checkField(t, entry, "title", "Reflected XSS in search")
	checkField(t, entry, "type", "xss")
	checkField(t, entry, "url", "https://example.com/search?q=<script>")
	checkField(t, entry, "severity", "high")
	checkField(t, entry, "evidence", "alert(1) executed")
	checkField(t, entry, "tool", "dalfox")

	verified, ok := entry["verified"].(bool)
	if !ok || !verified {
		t.Errorf("expected verified=true, got %v", entry["verified"])
	}
}

// TestExtractBugs_MultipleBugs verifies that multiple bugs are all converted.
func TestExtractBugs_MultipleBugs(t *testing.T) {
	bugs := []brain.Bug{
		{ID: "ssrf_001", Type: "ssrf", URL: "https://example.com/fetch", Severity: "critical"},
		{ID: "idor_001", Type: "idor", URL: "https://example.com/api/user/2", Severity: "high"},
		{ID: "sqli_001", Type: "sqli", URL: "https://example.com/login", Severity: "critical"},
	}

	result := extractBugs(bugs)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}

	// Verify each bug's type is preserved
	types := []string{"ssrf", "idor", "sqli"}
	for i, expected := range types {
		if got, ok := result[i]["type"].(string); !ok || got != expected {
			t.Errorf("entry[%d]: expected type=%q, got %v", i, expected, result[i]["type"])
		}
	}
}

// TestExtractBugs_CVEFieldOmittedWhenEmpty verifies that the CVE field is only
// included in the map when it is non-empty.
func TestExtractBugs_CVEFieldOmittedWhenEmpty(t *testing.T) {
	bugsWithoutCVE := []brain.Bug{
		{ID: "xss_001", Type: "xss", URL: "https://example.com", Severity: "high"},
	}
	result := extractBugs(bugsWithoutCVE)
	if _, exists := result[0]["cve"]; exists {
		t.Error("expected CVE field to be absent when bug.CVE is empty")
	}

	bugsWithCVE := []brain.Bug{
		{ID: "log4j_001", Type: "rce", URL: "https://example.com", Severity: "critical", CVE: "CVE-2021-44228"},
	}
	result = extractBugs(bugsWithCVE)
	if cve, ok := result[0]["cve"].(string); !ok || cve != "CVE-2021-44228" {
		t.Errorf("expected CVE=CVE-2021-44228, got %v", result[0]["cve"])
	}
}

// TestExtractBugs_PreservesAllRequiredFields verifies that all required fields
// are present in every converted bug map.
func TestExtractBugs_PreservesAllRequiredFields(t *testing.T) {
	requiredFields := []string{"id", "title", "type", "url", "severity", "evidence", "poc", "tool", "verified"}

	bugs := []brain.Bug{
		{
			ID:       "test_001",
			Title:    "Test Bug",
			Type:     "xss",
			URL:      "https://example.com",
			Severity: "medium",
			Evidence: "some evidence",
			PoC:      "some poc",
			Tool:     "nuclei",
			Verified: false,
		},
	}

	result := extractBugs(bugs)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	for _, field := range requiredFields {
		if _, exists := result[0][field]; !exists {
			t.Errorf("required field %q missing from extracted bug map", field)
		}
	}
}

// TestExtractBugs_BrainMemoryIntegration verifies that bugs loaded from
// Brain_Memory (via brain.LoadTarget) can be correctly extracted.
// This tests the full pipeline: Brain_Memory → extractBugs → API payload.
//
// Validates: Requirements 5.3
func TestExtractBugs_BrainMemoryIntegration(t *testing.T) {
	// Simulate what brain.LoadTarget returns
	mem := &brain.TargetMemory{
		Target: "example.com",
		BugsFound: []brain.Bug{
			{
				ID:       "ssrf_001",
				Title:    "SSRF via URL parameter",
				Type:     "ssrf",
				URL:      "https://example.com/fetch?url=",
				Severity: "critical",
				Evidence: "Internal metadata endpoint reached",
				PoC:      "1. Send request with url=http://169.254.169.254/",
				Tool:     "nuclei",
				Verified: true,
				FoundAt:  time.Now(),
			},
			{
				ID:       "idor_001",
				Title:    "IDOR on user profile",
				Type:     "idor",
				URL:      "https://example.com/api/user/2",
				Severity: "high",
				Evidence: "Accessed another user's data",
				PoC:      "1. Change user ID in request from 1 to 2",
				Tool:     "manual",
				Verified: true,
				FoundAt:  time.Now(),
			},
		},
	}

	// Verify we have enough bugs for chain analysis
	if len(mem.BugsFound) < 2 {
		t.Fatal("test setup error: need at least 2 bugs")
	}

	// Extract bugs
	bugMaps := extractBugs(mem.BugsFound)
	if len(bugMaps) != 2 {
		t.Fatalf("expected 2 bug maps, got %d", len(bugMaps))
	}

	// Verify first bug
	if got := bugMaps[0]["type"]; got != "ssrf" {
		t.Errorf("expected type=ssrf, got %v", got)
	}
	if got := bugMaps[0]["severity"]; got != "critical" {
		t.Errorf("expected severity=critical, got %v", got)
	}

	// Verify second bug
	if got := bugMaps[1]["type"]; got != "idor" {
		t.Errorf("expected type=idor, got %v", got)
	}
}

// ─── Chain Display Formatting Tests ──────────────────────────────────────────
// Validates: Requirements 5.6

// TestFormatChainLine_BasicFormat verifies the "Chain N: vuln1 + vuln2 -> impact" format.
func TestFormatChainLine_BasicFormat(t *testing.T) {
	tests := []struct {
		id     int
		vulns  []string
		impact string
		want   string
	}{
		{
			id:     1,
			vulns:  []string{"SSRF", "IDOR"},
			impact: "PII leak via internal API pivot",
			want:   "Chain 1: SSRF + IDOR -> PII leak via internal API pivot",
		},
		{
			id:     2,
			vulns:  []string{"XSS", "CSRF"},
			impact: "Account takeover",
			want:   "Chain 2: XSS + CSRF -> Account takeover",
		},
		{
			id:     3,
			vulns:  []string{"SQLi", "RCE", "LFI"},
			impact: "Full server compromise",
			want:   "Chain 3: SQLi + RCE + LFI -> Full server compromise",
		},
	}

	for _, tt := range tests {
		got := formatChainLine(tt.id, tt.vulns, tt.impact)
		if got != tt.want {
			t.Errorf("formatChainLine(%d, %v, %q) = %q, want %q",
				tt.id, tt.vulns, tt.impact, got, tt.want)
		}
	}
}

// TestFormatChainLine_SingleVuln verifies formatting with a single vulnerability.
func TestFormatChainLine_SingleVuln(t *testing.T) {
	got := formatChainLine(1, []string{"RCE"}, "Full server compromise")
	want := "Chain 1: RCE -> Full server compromise"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestFormatChainLine_StartsWithChain verifies the output always starts with "Chain N:".
func TestFormatChainLine_StartsWithChain(t *testing.T) {
	for i := 1; i <= 10; i++ {
		line := formatChainLine(i, []string{"XSS", "IDOR"}, "account takeover")
		prefix := "Chain " + strings.TrimSpace(strings.Split(line, ":")[0][6:]) + ":"
		if !strings.HasPrefix(line, "Chain ") {
			t.Errorf("chain line %d does not start with 'Chain ': %q", i, line)
		}
		_ = prefix
	}
}

// TestFormatChainLine_ContainsArrow verifies the output always contains "->".
func TestFormatChainLine_ContainsArrow(t *testing.T) {
	line := formatChainLine(1, []string{"SSRF", "IDOR"}, "PII leak")
	if !strings.Contains(line, "->") {
		t.Errorf("chain line does not contain '->': %q", line)
	}
}

// TestParseChainLines_ExtractsChainHeaders verifies that chain header lines
// are correctly extracted from AI response text.
func TestParseChainLines_ExtractsChainHeaders(t *testing.T) {
	aiResponse := `Here are the exploit chains I identified:

Chain 1: SSRF + IDOR -> PII leak via internal API pivot
This chain starts by triggering the SSRF vulnerability...

Chain 2: XSS + CSRF -> Account takeover
The attacker first injects a script...

Chain 3: SQLi + RCE -> Full server compromise
By exploiting the SQL injection...`

	lines := parseChainLines(aiResponse)
	if len(lines) != 3 {
		t.Fatalf("expected 3 chain lines, got %d: %v", len(lines), lines)
	}

	if !strings.HasPrefix(lines[0], "Chain 1:") {
		t.Errorf("expected lines[0] to start with 'Chain 1:', got %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "Chain 2:") {
		t.Errorf("expected lines[1] to start with 'Chain 2:', got %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "Chain 3:") {
		t.Errorf("expected lines[2] to start with 'Chain 3:', got %q", lines[2])
	}
}

// TestParseChainLines_EmptyResponse verifies that an empty response returns
// an empty slice.
func TestParseChainLines_EmptyResponse(t *testing.T) {
	lines := parseChainLines("")
	if len(lines) != 0 {
		t.Errorf("expected empty slice for empty response, got %v", lines)
	}
}

// TestParseChainLines_NoChains verifies that a response with no chain headers
// returns an empty slice.
func TestParseChainLines_NoChains(t *testing.T) {
	aiResponse := `I analyzed the bugs but found no chainable vulnerabilities.
The bugs are isolated and cannot be combined for greater impact.`

	lines := parseChainLines(aiResponse)
	if len(lines) != 0 {
		t.Errorf("expected empty slice, got %v", lines)
	}
}

// TestExtractVulnTypes_BasicParsing verifies that vuln types are correctly
// extracted from a chain line.
func TestExtractVulnTypes_BasicParsing(t *testing.T) {
	tests := []struct {
		chainLine string
		want      []string
	}{
		{
			chainLine: "Chain 1: SSRF + IDOR -> PII leak",
			want:      []string{"SSRF", "IDOR"},
		},
		{
			chainLine: "Chain 2: XSS + CSRF -> Account takeover",
			want:      []string{"XSS", "CSRF"},
		},
		{
			chainLine: "Chain 3: SQLi + RCE + LFI -> Full compromise",
			want:      []string{"SQLi", "RCE", "LFI"},
		},
	}

	for _, tt := range tests {
		got := extractVulnTypes(tt.chainLine)
		if len(got) != len(tt.want) {
			t.Errorf("extractVulnTypes(%q): got %v, want %v", tt.chainLine, got, tt.want)
			continue
		}
		for i, v := range tt.want {
			if got[i] != v {
				t.Errorf("extractVulnTypes(%q)[%d]: got %q, want %q", tt.chainLine, i, got[i], v)
			}
		}
	}
}

// TestExtractVulnTypes_MalformedLine verifies graceful handling of malformed
// chain lines.
func TestExtractVulnTypes_MalformedLine(t *testing.T) {
	// Should not panic and should return a non-empty fallback
	got := extractVulnTypes("not a chain line")
	if len(got) == 0 {
		t.Error("expected non-empty fallback for malformed chain line")
	}
}

// TestExtractPoCForChain_ExtractsCorrectSection verifies that PoC steps for
// a specific chain are correctly extracted from the AI response.
func TestExtractPoCForChain_ExtractsCorrectSection(t *testing.T) {
	aiResponse := `Chain 1: SSRF + IDOR -> PII leak
1. Trigger SSRF to reach internal metadata endpoint
2. Use IDOR to access user data via internal API
3. Exfiltrate PII from response

Chain 2: XSS + CSRF -> Account takeover
1. Inject XSS payload in profile field
2. Craft CSRF token theft payload
3. Redirect victim to attacker-controlled page`

	poc1 := extractPoCForChain(aiResponse, 1)
	if !strings.Contains(poc1, "Trigger SSRF") {
		t.Errorf("expected PoC for chain 1 to contain SSRF step, got: %q", poc1)
	}
	if strings.Contains(poc1, "Inject XSS") {
		t.Errorf("PoC for chain 1 should not contain chain 2 steps, got: %q", poc1)
	}

	poc2 := extractPoCForChain(aiResponse, 2)
	if !strings.Contains(poc2, "Inject XSS") {
		t.Errorf("expected PoC for chain 2 to contain XSS step, got: %q", poc2)
	}
	if strings.Contains(poc2, "Trigger SSRF") {
		t.Errorf("PoC for chain 2 should not contain chain 1 steps, got: %q", poc2)
	}
}

// TestExtractPoCForChain_NonExistentChain verifies that requesting a chain
// that doesn't exist returns an empty string.
func TestExtractPoCForChain_NonExistentChain(t *testing.T) {
	aiResponse := `Chain 1: SSRF + IDOR -> PII leak
1. Step one`

	poc := extractPoCForChain(aiResponse, 99)
	if poc != "" {
		t.Errorf("expected empty string for non-existent chain, got: %q", poc)
	}
}

// ─── Helper ───────────────────────────────────────────────────────────────────

// checkField is a test helper that verifies a string field in a map.
func checkField(t *testing.T, m map[string]interface{}, key, expected string) {
	t.Helper()
	val, ok := m[key].(string)
	if !ok {
		t.Errorf("field %q: expected string, got %T (%v)", key, m[key], m[key])
		return
	}
	if val != expected {
		t.Errorf("field %q: expected %q, got %q", key, expected, val)
	}
}
