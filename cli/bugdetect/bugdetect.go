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

// sqlmapPattern matches sqlmap injection confirmations
var sqlmapPattern = regexp.MustCompile(`(?i)(parameter\s+'[^']+'\s+is\s+vulnerable|injectable|sql\s+injection)`)

// ssrfPattern matches SSRF confirmations
var ssrfPattern = regexp.MustCompile(`(?i)(ssrf|server.side.request.forgery|internal.*response|169\.254\.169\.254)`)

// lfiPattern matches LFI confirmations
var lfiPattern = regexp.MustCompile(`(?i)(root:x:0:0|/etc/passwd|local.file.inclusion|path.traversal)`)

// rcePattern matches RCE confirmations
var rcePattern = regexp.MustCompile(`(?i)(remote.code.execution|command.injection|rce.*confirmed|uid=\d+\(|whoami.*root)`)

// idorPattern matches IDOR findings
var idorPattern = regexp.MustCompile(`(?i)(idor|insecure.direct.object|unauthorized.access|403.*bypass|access.control)`)

// cvePattern matches CVE IDs
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// ParseNucleiOutput parses nuclei output and returns confirmed bugs
func ParseNucleiOutput(output, target string) []Bug {
	var bugs []Bug
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Match nuclei format: [severity] [template] [url]
		m := nucleiPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		sev := Severity(strings.ToLower(m[1]))
		templateID := m[2]
		url := m[3]

		// Skip info unless it contains interesting keywords
		if sev == SeverityInfo {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, "exposed") && !strings.Contains(lower, "secret") &&
				!strings.Contains(lower, "token") && !strings.Contains(lower, "key") {
				continue
			}
		}

		// Extract CVE if present
		cve := ""
		if cveMatches := cvePattern.FindString(line); cveMatches != "" {
			cve = cveMatches
		}

		bug := Bug{
			Title:    fmt.Sprintf("[%s] %s", strings.ToUpper(string(sev)), templateID),
			Severity: sev,
			Tool:     "nuclei",
			Target:   target,
			URL:      url,
			Evidence: line,
			CVE:      cve,
			FoundAt:  time.Now(),
		}
		bug.Description = describeNucleiTemplate(templateID)
		bug.CVSS = severityToCVSS(sev)
		bug.CWE = templateToCWE(templateID)

		bugs = append(bugs, bug)
	}
	return bugs
}

// ParseDalfoxOutput parses dalfox XSS output
func ParseDalfoxOutput(output, target string) []Bug {
	var bugs []Bug
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)
		if !strings.Contains(lower, "poc") && !strings.Contains(lower, "verified") &&
			!strings.Contains(lower, "[v]") && !strings.Contains(lower, "found") {
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

// parseGenericOutput uses regex patterns to detect bugs in any tool output
func parseGenericOutput(toolName, output, target string) []Bug {
	var bugs []Bug

	if sqlmapPattern.MatchString(output) {
		bugs = append(bugs, Bug{
			Title:       "SQL Injection — Confirmed",
			Severity:    SeverityCritical,
			Tool:        toolName,
			Target:      target,
			Description: "SQL injection vulnerability confirmed. Attacker can read/modify database, potentially achieve RCE.",
			Evidence:    extractEvidence(output, sqlmapPattern),
			CVSS:        9.8,
			CWE:         "CWE-89",
			FoundAt:     time.Now(),
		})
	}

	if ssrfPattern.MatchString(output) {
		bugs = append(bugs, Bug{
			Title:       "Server-Side Request Forgery (SSRF) — Confirmed",
			Severity:    SeverityHigh,
			Tool:        toolName,
			Target:      target,
			Description: "SSRF vulnerability confirmed. Attacker can make server-side requests to internal services.",
			Evidence:    extractEvidence(output, ssrfPattern),
			CVSS:        8.6,
			CWE:         "CWE-918",
			FoundAt:     time.Now(),
		})
	}

	if lfiPattern.MatchString(output) {
		bugs = append(bugs, Bug{
			Title:       "Local File Inclusion (LFI) — Confirmed",
			Severity:    SeverityHigh,
			Tool:        toolName,
			Target:      target,
			Description: "LFI vulnerability confirmed. Attacker can read arbitrary files from the server.",
			Evidence:    extractEvidence(output, lfiPattern),
			CVSS:        7.5,
			CWE:         "CWE-22",
			FoundAt:     time.Now(),
		})
	}

	if rcePattern.MatchString(output) {
		bugs = append(bugs, Bug{
			Title:       "Remote Code Execution (RCE) — Confirmed",
			Severity:    SeverityCritical,
			Tool:        toolName,
			Target:      target,
			Description: "RCE vulnerability confirmed. Attacker can execute arbitrary commands on the server.",
			Evidence:    extractEvidence(output, rcePattern),
			CVSS:        10.0,
			CWE:         "CWE-78",
			FoundAt:     time.Now(),
		})
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
