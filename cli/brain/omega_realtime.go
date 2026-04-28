// Package brain — OmegaRealtime provides real-time feedback during OMEGA execution.
// Streams tool output to AI for mid-execution course correction.
package brain

import (
	"fmt"
	"strings"
)

// RealtimeFeedback carries partial tool output for mid-execution analysis.
type RealtimeFeedback struct {
	Target      string
	Phase       string
	Tool        string
	OutputSoFar string
	BugsFound   int
	Confidence  float64
}

// CourseCorrection is the AI's response to partial tool output.
type CourseCorrection struct {
	ShouldStop bool     // stop current tool early
	ShouldSkip []string // skip these tools
	ShouldAdd  []string // add these tools
	NewFocus   string   // change vuln focus
	Reason     string
	Confidence float64
}

// AnalyzeRealtimeOutput analyzes partial tool output and suggests course corrections.
// Called after each tool runs in hunt phase to enable mid-execution adaptation.
func AnalyzeRealtimeOutput(fb RealtimeFeedback) CourseCorrection {
	correction := CourseCorrection{}
	lower := strings.ToLower(fb.OutputSoFar)

	// Early exit conditions — shell obtained, stop everything
	if strings.Contains(lower, "os-shell>") || strings.Contains(lower, "uid=0(root)") ||
		strings.Contains(lower, "uid=0(") {
		correction.ShouldStop = true
		correction.Reason = "Shell obtained — stop current tool, move to post-exploitation"
		correction.Confidence = 0.99
		return correction
	}

	// High-value finding detected mid-execution — pivot to exploitation
	if strings.Contains(lower, "[critical]") || strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "remote code execution") || strings.Contains(lower, "rce confirmed") {
		correction.NewFocus = "exploit"
		correction.Reason = "Critical finding detected — prioritize exploitation"
		correction.Confidence = 0.90
	}

	// WAF blocking — switch strategy
	if strings.Contains(lower, "403 forbidden") || strings.Contains(lower, "waf detected") ||
		strings.Contains(lower, "blocked by") || strings.Contains(lower, "access denied") {
		correction.ShouldAdd = []string{"waf-bypass"}
		correction.Reason = "WAF detected — adding bypass techniques"
		correction.Confidence = 0.75
	}

	// Rate limiting detected — slow down
	if strings.Contains(lower, "429 too many") || strings.Contains(lower, "rate limit") ||
		strings.Contains(lower, "too many requests") {
		correction.Reason = "Rate limiting detected — slowing down"
		correction.Confidence = 0.80
	}

	// Credentials found — pivot to credential reuse
	if strings.Contains(lower, "password") && (strings.Contains(lower, "found") || strings.Contains(lower, "cracked")) {
		correction.ShouldAdd = []string{"cred-reuse", "cred-reuse-ssh"}
		correction.Reason = "Credentials found — adding credential reuse testing"
		correction.Confidence = 0.85
	}

	// GraphQL detected — add GraphQL-specific tools
	if strings.Contains(lower, "graphql") || strings.Contains(lower, "introspection") {
		correction.ShouldAdd = []string{"nuclei-graphql"}
		correction.Reason = "GraphQL detected — adding GraphQL introspection testing"
		correction.Confidence = 0.80
	}

	// JWT detected — add JWT attack tools
	if strings.Contains(lower, "jwt") || strings.Contains(lower, "bearer token") ||
		strings.Contains(lower, "authorization: bearer") {
		correction.ShouldAdd = []string{"jwt_tool"}
		correction.Reason = "JWT authentication detected — adding JWT attack testing"
		correction.Confidence = 0.80
	}

	// Cloud metadata detected — add cloud exploitation
	if strings.Contains(lower, "169.254.169.254") || strings.Contains(lower, "metadata.google") ||
		strings.Contains(lower, "aws credentials") || strings.Contains(lower, "iam/security-credentials") {
		correction.NewFocus = "cloud"
		correction.ShouldAdd = []string{"pacu"}
		correction.Reason = "Cloud metadata/credentials detected — pivoting to cloud exploitation"
		correction.Confidence = 0.95
	}

	return correction
}

// GetAdaptiveWAFBypass returns WAF-specific bypass strategies for tools.
// Returns a map of tool → bypass flags/headers.
func GetAdaptiveWAFBypass(wafVendor string) map[string]string {
	bypasses := map[string]map[string]string{
		"cloudflare": {
			"sqlmap_tamper":   "space2comment,between,randomcase,charencode,equaltolike",
			"dalfox_bypass":   "--waf-evasion --skip-bav",
			"ffuf_headers":    "X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1",
			"nuclei_headers":  "X-Forwarded-For: 127.0.0.1",
			"nuclei_rate":     "5",
			"delay_ms":        "500",
		},
		"akamai": {
			"sqlmap_tamper":   "space2comment,between,charencode,randomcase",
			"dalfox_bypass":   "--waf-evasion",
			"ffuf_headers":    "X-Originating-IP: 127.0.0.1",
			"nuclei_headers":  "X-Originating-IP: 127.0.0.1",
			"nuclei_rate":     "10",
			"delay_ms":        "300",
		},
		"aws": {
			"sqlmap_tamper":   "space2comment,between,randomcase",
			"dalfox_bypass":   "--waf-evasion",
			"ffuf_headers":    "X-Forwarded-For: 127.0.0.1",
			"nuclei_headers":  "X-Forwarded-For: 127.0.0.1",
			"nuclei_rate":     "10",
			"delay_ms":        "200",
		},
		"imperva": {
			"sqlmap_tamper":   "space2comment,between,charencode,equaltolike,greatest",
			"dalfox_bypass":   "--waf-evasion --skip-bav",
			"ffuf_headers":    "X-Forwarded-For: 127.0.0.1\nTrue-Client-IP: 127.0.0.1",
			"nuclei_headers":  "X-Forwarded-For: 127.0.0.1",
			"nuclei_rate":     "5",
			"delay_ms":        "1000",
		},
		"f5": {
			"sqlmap_tamper":   "space2comment,between,randomcase,charencode",
			"dalfox_bypass":   "--waf-evasion",
			"ffuf_headers":    "X-Forwarded-For: 127.0.0.1",
			"nuclei_headers":  "X-Forwarded-For: 127.0.0.1",
			"nuclei_rate":     "10",
			"delay_ms":        "300",
		},
		"sucuri": {
			"sqlmap_tamper":   "space2comment,between,randomcase",
			"dalfox_bypass":   "--waf-evasion",
			"ffuf_headers":    "X-Forwarded-For: 127.0.0.1",
			"nuclei_headers":  "X-Forwarded-For: 127.0.0.1",
			"nuclei_rate":     "5",
			"delay_ms":        "500",
		},
	}

	vendor := strings.ToLower(wafVendor)
	for k, v := range bypasses {
		if strings.Contains(vendor, k) {
			return v
		}
	}

	// Generic bypass — works for most WAFs
	return map[string]string{
		"sqlmap_tamper":  "space2comment,between,randomcase",
		"dalfox_bypass":  "--waf-evasion",
		"ffuf_headers":   "X-Forwarded-For: 127.0.0.1",
		"nuclei_headers": "X-Forwarded-For: 127.0.0.1",
		"nuclei_rate":    "10",
		"delay_ms":       "200",
	}
}

// GetCredentialReuseTargets returns services to test with found credentials.
// Uses open ports to determine which services are available.
func GetCredentialReuseTargets(target string, openPorts []int) []string {
	var targets []string
	portServices := map[int]string{
		22:    "ssh",
		21:    "ftp",
		445:   "smb",
		3389:  "rdp",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
		8080:  "http",
		8443:  "https",
		5900:  "vnc",
		23:    "telnet",
		25:    "smtp",
		110:   "pop3",
		143:   "imap",
	}
	for _, port := range openPorts {
		if svc, ok := portServices[port]; ok {
			targets = append(targets, fmt.Sprintf("%s://%s:%d", svc, target, port))
		}
	}
	return targets
}

// ApplyWAFBypassToArgs applies WAF bypass flags to tool arguments.
// Returns modified args with bypass techniques applied.
func ApplyWAFBypassToArgs(toolName string, args []string, bypass map[string]string) []string {
	if len(bypass) == 0 {
		return args
	}

	switch toolName {
	case "sqlmap":
		if tamper, ok := bypass["sqlmap_tamper"]; ok {
			// Replace or add tamper flag
			for i, arg := range args {
				if arg == "--tamper" && i+1 < len(args) {
					args[i+1] = tamper
					return args
				}
			}
			args = append(args, "--tamper", tamper)
		}
		if delay, ok := bypass["delay_ms"]; ok {
			args = append(args, "--delay", delay)
		}

	case "dalfox":
		if bypassFlags, ok := bypass["dalfox_bypass"]; ok {
			for _, flag := range strings.Fields(bypassFlags) {
				args = append(args, flag)
			}
		}

	case "nuclei":
		if headers, ok := bypass["nuclei_headers"]; ok {
			args = append(args, "-H", headers)
		}
		if rate, ok := bypass["nuclei_rate"]; ok {
			// Replace rate limit
			for i, arg := range args {
				if arg == "-rl" && i+1 < len(args) {
					args[i+1] = rate
					return args
				}
			}
			args = append(args, "-rl", rate)
		}

	case "ffuf":
		if headers, ok := bypass["ffuf_headers"]; ok {
			for _, header := range strings.Split(headers, "\n") {
				if header != "" {
					args = append(args, "-H", header)
				}
			}
		}
	}

	return args
}
