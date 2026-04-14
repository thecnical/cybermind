// js_intel.go — Gap 6: JavaScript Intelligence Layer
// Extracts API keys, hidden endpoints, GraphQL schemas, internal URLs from JS files.
package brain

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// JSFinding represents something found in JavaScript files.
type JSFinding struct {
	Type     string // "api_key", "endpoint", "secret", "graphql_schema", "internal_url"
	Value    string
	Source   string // JS file URL where found
	Severity string
}

// JSIntelResult holds all findings from JS analysis.
type JSIntelResult struct {
	JSFiles  []string
	Findings []JSFinding
	Endpoints []string // discovered API endpoints
	Secrets   []string // API keys, tokens, passwords
}

// ─── Patterns ─────────────────────────────────────────────────────────────────

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
	severity string
}{
	{"AWS Access Key",     regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "critical"},
	{"AWS Secret Key",     regexp.MustCompile(`[0-9a-zA-Z/+]{40}`), "critical"},
	{"Google API Key",     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "high"},
	{"GitHub Token",       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), "critical"},
	{"GitHub OAuth",       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), "critical"},
	{"Stripe Secret",      regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), "critical"},
	{"Stripe Publishable", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`), "medium"},
	{"Slack Token",        regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`), "high"},
	{"Slack Webhook",      regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9/]+`), "high"},
	{"JWT Token",          regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "medium"},
	{"Private Key",        regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), "critical"},
	{"Firebase URL",       regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`), "medium"},
	{"Heroku API Key",     regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), "high"},
	{"Generic API Key",    regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?secret)['":\s=]+['"]?([a-zA-Z0-9_\-]{20,})`), "medium"},
	{"Generic Password",   regexp.MustCompile(`(?i)(password|passwd|pwd)['":\s=]+['"]([^'"]{8,})`), "high"},
	{"Generic Token",      regexp.MustCompile(`(?i)(token|auth[_-]?token|access[_-]?token)['":\s=]+['"]([a-zA-Z0-9_\-\.]{20,})`), "medium"},
}

var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_\-{}]+)["']`),
	regexp.MustCompile(`["'](/v[0-9]+/[a-zA-Z0-9/_\-{}]+)["']`),
	regexp.MustCompile(`["'](https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9/_\-{}?=&]+)["']`),
	regexp.MustCompile(`fetch\(['"]([^'"]+)['"]\)`),
	regexp.MustCompile(`axios\.[a-z]+\(['"]([^'"]+)['"]\)`),
	regexp.MustCompile(`\$\.ajax\(\{[^}]*url:\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`XMLHttpRequest.*open\(['"][A-Z]+['"],\s*['"]([^'"]+)['"]`),
}

// ─── JS Analysis ──────────────────────────────────────────────────────────────

// AnalyzeJSFiles runs full JS intelligence analysis on a target.
func AnalyzeJSFiles(target string, liveURLs []string) JSIntelResult {
	result := JSIntelResult{}

	// 1. Collect JS file URLs
	jsFiles := collectJSFiles(target, liveURLs)
	result.JSFiles = jsFiles

	// 2. Analyze each JS file
	client := &http.Client{Timeout: 15 * time.Second}
	for _, jsURL := range jsFiles {
		resp, err := client.Get(jsURL)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB max per file
		resp.Body.Close()
		if err != nil {
			continue
		}
		content := string(body)

		// Find secrets
		for _, pattern := range secretPatterns {
			matches := pattern.pattern.FindAllString(content, -1)
			for _, match := range matches {
				// Skip obvious false positives
				if isObviousFalsePositive(match) {
					continue
				}
				result.Findings = append(result.Findings, JSFinding{
					Type:     "secret",
					Value:    truncateSecret(match),
					Source:   jsURL,
					Severity: pattern.severity,
				})
				result.Secrets = append(result.Secrets, match)
			}
		}

		// Find endpoints
		for _, pattern := range endpointPatterns {
			matches := pattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					endpoint := match[1]
					if isValidEndpoint(endpoint) {
						result.Endpoints = append(result.Endpoints, endpoint)
						result.Findings = append(result.Findings, JSFinding{
							Type:     "endpoint",
							Value:    endpoint,
							Source:   jsURL,
							Severity: "info",
						})
					}
				}
			}
		}
	}

	// 3. Use specialized tools if available
	if _, err := exec.LookPath("mantra"); err == nil {
		mantraFindings := runMantra(target)
		result.Findings = append(result.Findings, mantraFindings...)
	}

	// Deduplicate endpoints
	result.Endpoints = deduplicateWords(result.Endpoints)
	result.Secrets = deduplicateWords(result.Secrets)

	return result
}

// collectJSFiles finds all JavaScript files for a target.
func collectJSFiles(target string, liveURLs []string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	// Common JS file locations
	commonPaths := []string{
		"/static/js/main.js",
		"/static/js/bundle.js",
		"/assets/js/app.js",
		"/js/app.js",
		"/app.js",
		"/bundle.js",
		"/main.js",
		"/dist/bundle.js",
		"/build/static/js/main.chunk.js",
	}

	baseURL := "https://" + strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range commonPaths {
		url := baseURL + path
		resp, err := client.Head(url)
		if err == nil && resp.StatusCode == 200 {
			if !seen[url] {
				seen[url] = true
				jsFiles = append(jsFiles, url)
			}
		}
	}

	// Extract JS files from live URLs
	for _, u := range liveURLs {
		if strings.HasSuffix(u, ".js") && !seen[u] {
			seen[u] = true
			jsFiles = append(jsFiles, u)
		}
	}

	return jsFiles
}

// runMantra runs the mantra tool for API key detection.
func runMantra(target string) []JSFinding {
	var findings []JSFinding
	url := "https://" + strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")

	cmd := exec.Command("mantra", "-u", url, "-s")
	out, err := runWithTimeout(cmd, 120)
	if err != nil {
		return findings
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			findings = append(findings, JSFinding{
				Type:     "secret",
				Value:    line,
				Source:   url,
				Severity: "high",
			})
		}
	}
	return findings
}

// ─── WAF Bypass Intelligence (Gap 8) ─────────────────────────────────────────

// WAFBypassStrategy holds bypass techniques for a specific WAF vendor.
type WAFBypassStrategy struct {
	Vendor      string
	Techniques  []string
	Headers     map[string]string // headers to add for bypass
	Delays      int               // ms between requests
	Encodings   []string          // encoding techniques to try
	UserAgents  []string          // UA strings that bypass WAF
}

// GetWAFBypassStrategy returns the optimal bypass strategy for a WAF vendor.
func GetWAFBypassStrategy(vendor string) WAFBypassStrategy {
	strategies := map[string]WAFBypassStrategy{
		"cloudflare": {
			Vendor: "Cloudflare",
			Techniques: []string{
				"Use legitimate-looking User-Agent (Googlebot)",
				"Add X-Forwarded-For: 127.0.0.1",
				"Use chunked transfer encoding",
				"Encode payloads with HTML entities",
				"Use Unicode normalization bypass",
				"Add Cf-Connecting-IP: 127.0.0.1",
			},
			Headers: map[string]string{
				"X-Forwarded-For":   "127.0.0.1",
				"X-Real-IP":         "127.0.0.1",
				"CF-Connecting-IP":  "127.0.0.1",
				"X-Originating-IP":  "127.0.0.1",
			},
			Delays:    500,
			Encodings: []string{"url", "html", "unicode", "base64"},
			UserAgents: []string{
				"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			},
		},
		"akamai": {
			Vendor: "Akamai",
			Techniques: []string{
				"Use True-Client-IP header manipulation",
				"Vary request timing (slow down)",
				"Use HTTP/2 for requests",
				"Fragment payloads across parameters",
				"Use Akamai-specific header bypass",
			},
			Headers: map[string]string{
				"True-Client-IP":   "127.0.0.1",
				"X-Forwarded-For":  "127.0.0.1",
			},
			Delays:    1000,
			Encodings: []string{"url", "double-url", "html"},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
		},
		"imperva": {
			Vendor: "Imperva/Incapsula",
			Techniques: []string{
				"Use X-Forwarded-For with internal IP",
				"Encode with multiple encoding layers",
				"Use HTTP parameter pollution",
				"Fragment SQL/XSS payloads",
			},
			Headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
				"X-Remote-IP":     "127.0.0.1",
			},
			Delays:    2000,
			Encodings: []string{"url", "double-url", "unicode"},
			UserAgents: []string{
				"Mozilla/5.0 (compatible; Googlebot/2.1)",
			},
		},
		"aws-waf": {
			Vendor: "AWS WAF",
			Techniques: []string{
				"Use JSON body instead of form data",
				"Vary Content-Type headers",
				"Use AWS-specific header bypass",
				"Fragment payloads in JSON arrays",
			},
			Headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			Delays:    300,
			Encodings: []string{"url", "json"},
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			},
		},
	}

	vendorLower := strings.ToLower(vendor)
	for key, strategy := range strategies {
		if strings.Contains(vendorLower, key) {
			return strategy
		}
	}

	// Default bypass strategy
	return WAFBypassStrategy{
		Vendor: vendor,
		Techniques: []string{
			"Use X-Forwarded-For: 127.0.0.1",
			"Encode payloads with URL encoding",
			"Add legitimate User-Agent",
			"Slow down request rate",
		},
		Headers: map[string]string{
			"X-Forwarded-For": "127.0.0.1",
			"X-Real-IP":       "127.0.0.1",
		},
		Delays:    500,
		Encodings: []string{"url", "html"},
		UserAgents: []string{
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		},
	}
}

// ApplyWAFBypass applies WAF bypass headers to an HTTP request.
func ApplyWAFBypass(req *http.Request, strategy WAFBypassStrategy) {
	for k, v := range strategy.Headers {
		req.Header.Set(k, v)
	}
	if len(strategy.UserAgents) > 0 {
		req.Header.Set("User-Agent", strategy.UserAgents[0])
	}
}

// FormatWAFBypassReport returns a human-readable WAF bypass strategy.
func FormatWAFBypassReport(strategy WAFBypassStrategy) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  🛡  WAF: %s — Bypass Strategy:\n", strategy.Vendor))
	for i, t := range strategy.Techniques {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, t))
	}
	sb.WriteString(fmt.Sprintf("  ⏱  Request delay: %dms\n", strategy.Delays))
	sb.WriteString(fmt.Sprintf("  🔤 Encodings: %s\n", strings.Join(strategy.Encodings, ", ")))
	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isObviousFalsePositive(match string) bool {
	fps := []string{
		"example", "placeholder", "your_key", "YOUR_KEY",
		"xxxxxxxx", "XXXXXXXX", "00000000",
		"test", "demo", "sample",
	}
	lower := strings.ToLower(match)
	for _, fp := range fps {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	return false
}

func truncateSecret(secret string) string {
	if len(secret) > 20 {
		return secret[:8] + "..." + secret[len(secret)-4:]
	}
	return secret
}

func isValidEndpoint(endpoint string) bool {
	if len(endpoint) < 3 || len(endpoint) > 200 {
		return false
	}
	// Must start with / or http
	if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "http") {
		return false
	}
	// Skip static assets
	staticExts := []string{".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf"}
	for _, ext := range staticExts {
		if strings.HasSuffix(endpoint, ext) {
			return false
		}
	}
	return true
}
