package osint

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// checkBreachAPIs queries free breach APIs for a target (email or @domain).
// Called automatically after Phase 2 in RunOSINTDeep.
// Priority: HIBP free → LeakCheck → BreachDirectory
// No API key required for basic checks.
func checkBreachAPIs(target string) string {
	var results []string

	// 1. HIBP free check (email only)
	if strings.Contains(target, "@") && !strings.HasPrefix(target, "@") {
		if r := hibpFreeCheck(target); r != "" {
			results = append(results, "[HIBP] "+r)
		}
	}

	// 2. LeakCheck.io free API (email + domain)
	if r := leakCheckFree(target); r != "" {
		results = append(results, "[LeakCheck] "+r)
	}

	// 3. BreachDirectory free check
	if strings.Contains(target, "@") && !strings.HasPrefix(target, "@") {
		if r := breachDirFree(target); r != "" {
			results = append(results, "[BreachDir] "+r)
		}
	}

	return strings.Join(results, "\n")
}

var breachHTTPClient = &http.Client{Timeout: 8 * time.Second}

// hibpFreeCheck queries HIBP v3 without API key (truncated response).
func hibpFreeCheck(email string) string {
	reqURL := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s",
		url.PathEscape(email))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

	resp, err := breachHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return fmt.Sprintf("%s — not found in HIBP", email)
	}
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		// Count breaches from JSON array
		count := strings.Count(string(body), `"Name"`)
		if count > 0 {
			return fmt.Sprintf("%s — FOUND in %d breaches! %s", email, count, string(body[:min(200, len(body))]))
		}
	}
	if resp.StatusCode == 401 {
		return fmt.Sprintf("%s — HIBP requires API key for full results", email)
	}
	return ""
}

// leakCheckFree queries LeakCheck.io public API.
func leakCheckFree(target string) string {
	reqURL := fmt.Sprintf("https://leakcheck.io/api/public?check=%s", url.QueryEscape(target))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

	resp, err := breachHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if strings.Contains(bodyStr, `"found":0`) || strings.Contains(bodyStr, `"success":false`) {
		return ""
	}
	if strings.Contains(bodyStr, `"found":`) {
		return fmt.Sprintf("%s — FOUND in LeakCheck: %s", target, bodyStr[:min(300, len(bodyStr))])
	}
	return ""
}

// breachDirFree queries BreachDirectory.org.
func breachDirFree(email string) string {
	reqURL := fmt.Sprintf("https://breachdirectory.org/api?func=auto&term=%s", url.QueryEscape(email))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

	resp, err := breachHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if strings.Contains(bodyStr, `"found":0`) || !strings.Contains(bodyStr, `"success":true`) {
		return ""
	}
	return fmt.Sprintf("%s — FOUND in BreachDirectory: %s", email, bodyStr[:min(300, len(bodyStr))])
}
