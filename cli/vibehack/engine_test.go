package vibehack

import (
	"strings"
	"testing"
	"time"
)

// ─── SSE Event Parsing Tests ──────────────────────────────────────────────────
// Validates: Requirements 3.3, 3.8

func TestParseSSEEvent_Start(t *testing.T) {
	data := `{"type":"start","target":"example.com","step":0}`
	ev := parseSSEEvent(data)
	if ev == nil {
		t.Fatal("expected non-nil event for start type")
	}
	if ev.Type != "start" {
		t.Errorf("expected type 'start', got %q", ev.Type)
	}
	if ev.Target != "example.com" {
		t.Errorf("expected target 'example.com', got %q", ev.Target)
	}
	if ev.Step != 0 {
		t.Errorf("expected step 0, got %d", ev.Step)
	}
}

func TestParseSSEEvent_Step(t *testing.T) {
	data := `{"type":"step","step":3,"tool":"sqlmap","reasoning":"Found PHP + MySQL -> trying SQLi next","output":"[INFO] testing connection"}`
	ev := parseSSEEvent(data)
	if ev == nil {
		t.Fatal("expected non-nil event for step type")
	}
	if ev.Type != "step" {
		t.Errorf("expected type 'step', got %q", ev.Type)
	}
	if ev.Step != 3 {
		t.Errorf("expected step 3, got %d", ev.Step)
	}
	if ev.Tool != "sqlmap" {
		t.Errorf("expected tool 'sqlmap', got %q", ev.Tool)
	}
	if ev.Reasoning != "Found PHP + MySQL -> trying SQLi next" {
		t.Errorf("unexpected reasoning: %q", ev.Reasoning)
	}
	if ev.Output != "[INFO] testing connection" {
		t.Errorf("unexpected output: %q", ev.Output)
	}
}

func TestParseSSEEvent_Finding(t *testing.T) {
	data := `{"type":"finding","severity":"critical","vuln_type":"SQLi","evidence":"' OR 1=1-- returned 200"}`
	ev := parseSSEEvent(data)
	if ev == nil {
		t.Fatal("expected non-nil event for finding type")
	}
	if ev.Type != "finding" {
		t.Errorf("expected type 'finding', got %q", ev.Type)
	}
	if ev.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", ev.Severity)
	}
	if ev.VulnType != "SQLi" {
		t.Errorf("expected vuln type 'SQLi', got %q", ev.VulnType)
	}
	if ev.Evidence != "' OR 1=1-- returned 200" {
		t.Errorf("unexpected evidence: %q", ev.Evidence)
	}
}

func TestParseSSEEvent_Complete(t *testing.T) {
	data := `{"type":"complete","steps":12,"findings":2}`
	ev := parseSSEEvent(data)
	if ev == nil {
		t.Fatal("expected non-nil event for complete type")
	}
	if ev.Type != "complete" {
		t.Errorf("expected type 'complete', got %q", ev.Type)
	}
	if ev.Steps != 12 {
		t.Errorf("expected steps 12, got %d", ev.Steps)
	}
	if ev.Findings != 2 {
		t.Errorf("expected findings 2, got %d", ev.Findings)
	}
}

func TestParseSSEEvent_Error(t *testing.T) {
	data := `{"type":"error","message":"Pro plan required"}`
	ev := parseSSEEvent(data)
	if ev == nil {
		t.Fatal("expected non-nil event for error type")
	}
	if ev.Type != "error" {
		t.Errorf("expected type 'error', got %q", ev.Type)
	}
	if ev.Message != "Pro plan required" {
		t.Errorf("expected message 'Pro plan required', got %q", ev.Message)
	}
}

func TestParseSSEEvent_Empty(t *testing.T) {
	ev := parseSSEEvent("")
	if ev != nil {
		t.Errorf("expected nil for empty input, got %+v", ev)
	}
}

func TestParseSSEEvent_Whitespace(t *testing.T) {
	ev := parseSSEEvent("   \t  ")
	if ev != nil {
		t.Errorf("expected nil for whitespace-only input, got %+v", ev)
	}
}

func TestParseSSEEvent_InvalidJSON(t *testing.T) {
	ev := parseSSEEvent("not json at all")
	if ev != nil {
		t.Errorf("expected nil for invalid JSON, got %+v", ev)
	}
}

func TestParseSSEEvent_MalformedJSON(t *testing.T) {
	ev := parseSSEEvent(`{"type":"step","step":`)
	if ev != nil {
		t.Errorf("expected nil for malformed JSON, got %+v", ev)
	}
}

// ─── Session Transcript Formatting Tests ─────────────────────────────────────
// Validates: Requirements 3.8

func makeTestSession() *VibeHackSession {
	start := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	end := start.Add(5*time.Minute + 30*time.Second)
	return &VibeHackSession{
		Target:    "example.com",
		StartTime: start,
		EndTime:   end,
		Steps: []VibeStep{
			{N: 1, Tool: "nmap", Reasoning: "Initial port scan", Output: "80/tcp open"},
			{N: 2, Tool: "sqlmap", Reasoning: "Found PHP + MySQL -> trying SQLi next", Output: "vulnerable"},
		},
		Findings: []VibeFinding{
			{Severity: "critical", VulnType: "SQLi", Evidence: "' OR 1=1-- returned 200"},
			{Severity: "high", VulnType: "XSS", Evidence: "<script>alert(1)</script> reflected"},
		},
	}
}

func TestBuildTranscript_ContainsTarget(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "example.com") {
		t.Error("transcript should contain the target")
	}
}

func TestBuildTranscript_ContainsStepCount(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "Steps:    2") {
		t.Errorf("transcript should contain step count 2, got:\n%s", transcript)
	}
}

func TestBuildTranscript_ContainsFindingCount(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "Findings: 2") {
		t.Errorf("transcript should contain finding count 2, got:\n%s", transcript)
	}
}

func TestBuildTranscript_ContainsStepDetails(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "nmap") {
		t.Error("transcript should contain tool name 'nmap'")
	}
	if !strings.Contains(transcript, "Found PHP + MySQL -> trying SQLi next") {
		t.Error("transcript should contain step reasoning")
	}
}

func TestBuildTranscript_ContainsFindingDetails(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "CRITICAL") {
		t.Error("transcript should contain severity 'CRITICAL'")
	}
	if !strings.Contains(transcript, "SQLi") {
		t.Error("transcript should contain vuln type 'SQLi'")
	}
	if !strings.Contains(transcript, "' OR 1=1-- returned 200") {
		t.Error("transcript should contain evidence")
	}
}

func TestBuildTranscript_ContainsElapsedTime(t *testing.T) {
	session := makeTestSession()
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "Elapsed:") {
		t.Error("transcript should contain elapsed time")
	}
	// 5m30s elapsed
	if !strings.Contains(transcript, "5m30s") {
		t.Errorf("transcript should contain '5m30s', got:\n%s", transcript)
	}
}

func TestBuildTranscript_EmptySession(t *testing.T) {
	session := &VibeHackSession{
		Target:    "empty-target.com",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Second),
	}
	transcript := buildTranscript(session)
	if !strings.Contains(transcript, "empty-target.com") {
		t.Error("transcript should contain target even for empty session")
	}
	if !strings.Contains(transcript, "Steps:    0") {
		t.Error("transcript should show 0 steps for empty session")
	}
	if !strings.Contains(transcript, "Findings: 0") {
		t.Error("transcript should show 0 findings for empty session")
	}
}

// ─── Session Summary Formatting Tests ────────────────────────────────────────

func TestBuildSummary_ContainsStepCount(t *testing.T) {
	session := makeTestSession()
	summary := buildSummary(session)
	if !strings.Contains(summary, "2") {
		t.Errorf("summary should contain step count, got:\n%s", summary)
	}
}

func TestBuildSummary_ContainsElapsedTime(t *testing.T) {
	session := makeTestSession()
	summary := buildSummary(session)
	if !strings.Contains(summary, "5m30s") {
		t.Errorf("summary should contain elapsed time '5m30s', got:\n%s", summary)
	}
}

func TestBuildSummary_ContainsVulnTypes(t *testing.T) {
	session := makeTestSession()
	summary := buildSummary(session)
	if !strings.Contains(summary, "SQLi") {
		t.Error("summary should list vuln type 'SQLi'")
	}
	if !strings.Contains(summary, "XSS") {
		t.Error("summary should list vuln type 'XSS'")
	}
}

func TestBuildSummary_ContainsSeverity(t *testing.T) {
	session := makeTestSession()
	summary := buildSummary(session)
	if !strings.Contains(summary, "CRITICAL") {
		t.Error("summary should show severity 'CRITICAL'")
	}
	if !strings.Contains(summary, "HIGH") {
		t.Error("summary should show severity 'HIGH'")
	}
}

func TestBuildSummary_NoFindings(t *testing.T) {
	session := &VibeHackSession{
		Target:    "clean.com",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(10 * time.Second),
		Steps:     []VibeStep{{N: 1, Tool: "nmap", Reasoning: "scan", Output: "nothing"}},
	}
	summary := buildSummary(session)
	if !strings.Contains(summary, "0") {
		t.Errorf("summary should show 0 vulnerabilities, got:\n%s", summary)
	}
}
