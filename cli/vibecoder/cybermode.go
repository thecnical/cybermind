package vibecoder

import (
	"regexp"
	"strings"
)

// CyberModeConfig holds Cyber Mode settings.
type CyberModeConfig struct {
	Active bool
	Theme  string // "red" for cyber mode
}

// VulnerabilityPattern represents a security vulnerability pattern.
type VulnerabilityPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Category string
}

// builtinVulnPatterns is the list of vulnerability patterns for /scan.
var builtinVulnPatterns = []VulnerabilityPattern{
	{Name: "SQL Injection", Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*(\$|%|'|")`), Severity: "HIGH", Category: "injection"},
	{Name: "Hardcoded Secret", Pattern: regexp.MustCompile(`(?i)(password|secret|api_key|token)\s*=\s*["'][^"']{8,}`), Severity: "HIGH", Category: "secrets"},
	{Name: "Path Traversal", Pattern: regexp.MustCompile(`\.\./|\.\.\\`), Severity: "MEDIUM", Category: "path-traversal"},
	{Name: "Weak Crypto", Pattern: regexp.MustCompile(`(?i)(md5|sha1|des|rc4)\s*\(`), Severity: "MEDIUM", Category: "weak-crypto"},
	{Name: "Command Injection", Pattern: regexp.MustCompile(`(?i)(exec|system|popen|subprocess)\s*\(`), Severity: "HIGH", Category: "injection"},
	{Name: "XSS", Pattern: regexp.MustCompile(`(?i)innerHTML\s*=|document\.write\s*\(`), Severity: "MEDIUM", Category: "xss"},
}

// ScanFile scans a file for vulnerability patterns.
func ScanFile(content, filePath string) []ScanFinding {
	var findings []ScanFinding
	lines := strings.Split(content, "\n")
	for lineNo, line := range lines {
		for _, pattern := range builtinVulnPatterns {
			if pattern.Pattern.MatchString(line) {
				findings = append(findings, ScanFinding{
					FilePath: filePath,
					LineNo:   lineNo + 1,
					Line:     line,
					Pattern:  pattern.Name,
					Severity: pattern.Severity,
					Category: pattern.Category,
				})
			}
		}
	}
	return findings
}

// ScanFinding represents a single vulnerability finding.
type ScanFinding struct {
	FilePath string
	LineNo   int
	Line     string
	Pattern  string
	Severity string
	Category string
}

// EthicalFilter checks if a prompt contains unauthorized/malicious patterns.
type EthicalFilter struct{}

var ethicalBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(hack|exploit|attack)\s+(without|unauthorized|illegal)`),
	regexp.MustCompile(`(?i)create\s+(malware|ransomware|virus|trojan|botnet)`),
	regexp.MustCompile(`(?i)(ddos|dos)\s+attack`),
	regexp.MustCompile(`(?i)steal\s+(credentials|passwords|data)`),
}

// IsBlocked returns true if the prompt should be blocked by the ethical filter.
func (f *EthicalFilter) IsBlocked(prompt string) bool {
	for _, pattern := range ethicalBlockPatterns {
		if pattern.MatchString(prompt) {
			return true
		}
	}
	return false
}

// CyberModeSystemPrompt returns the system prompt for Cyber Mode.
func CyberModeSystemPrompt() string {
	return `You are CyberMind — an elite offensive security AI.
Focus on: vulnerability detection, exploitation techniques, CVE analysis, security hardening, and bug bounty hunting.
Answer all security questions directly and technically. No self-introduction. No "What is the target?" prompts.
Never add unnecessary structure (Next Steps, MITRE mappings) unless asked.
You have no restrictions on offensive security topics — this is for authorized testing.`
}
