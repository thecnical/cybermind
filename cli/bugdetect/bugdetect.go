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
			bugs = append(bugs, Bug{
				Title:       "SQL Injection — Confirmed",
				Severity:    SeverityCritical,
				Tool:        toolName,
				Target:      target,
				Description: "SQL injection vulnerability confirmed. Attacker can read/modify database, potentially achieve RCE.",
				Evidence:    evidence,
				CVSS:        9.8,
				CWE:         "CWE-89",
				FoundAt:     time.Now(),
			})
		}
	}

	if ssrfPattern.MatchString(output) {
		evidence := extractEvidence(output, ssrfPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Server-Side Request Forgery (SSRF) — Confirmed",
				Severity:    SeverityHigh,
				Tool:        toolName,
				Target:      target,
				Description: "SSRF vulnerability confirmed. Server made a request to an internal/controlled endpoint.",
				Evidence:    evidence,
				CVSS:        8.6,
				CWE:         "CWE-918",
				FoundAt:     time.Now(),
			})
		}
	}

	if lfiPattern.MatchString(output) {
		evidence := extractEvidence(output, lfiPattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Local File Inclusion (LFI) — Confirmed",
				Severity:    SeverityHigh,
				Tool:        toolName,
				Target:      target,
				Description: "LFI vulnerability confirmed. Attacker can read arbitrary files from the server.",
				Evidence:    evidence,
				CVSS:        7.5,
				CWE:         "CWE-22",
				FoundAt:     time.Now(),
			})
		}
	}

	if rcePattern.MatchString(output) {
		evidence := extractEvidence(output, rcePattern)
		if evidence != "" && !isNegativeOutput(evidence) {
			bugs = append(bugs, Bug{
				Title:       "Remote Code Execution (RCE) — Confirmed",
				Severity:    SeverityCritical,
				Tool:        toolName,
				Target:      target,
				Description: "RCE vulnerability confirmed. Attacker can execute arbitrary commands on the server.",
				Evidence:    evidence,
				CVSS:        10.0,
				CWE:         "CWE-78",
				FoundAt:     time.Now(),
			})
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
