// Package bizlogic — Automated Business Logic Bug Hunter for CyberMind
//
// Detects: price manipulation, race conditions, negative quantities,
// IDOR chains, workflow bypass, coupon abuse, account takeover via logic flaws,
// mass assignment, privilege escalation via parameter tampering.
//
// How it works:
//  1. Crawls the target to discover API endpoints + parameters
//  2. Sends crafted requests with business logic payloads
//  3. Analyzes responses for anomalies (price changes, auth bypass, etc.)
//  4. Reports confirmed findings with PoC curl commands
package bizlogic

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Finding represents a confirmed business logic bug
type Finding struct {
	Type        string // "price_manipulation", "race_condition", "idor", etc.
	Severity    string // "critical", "high", "medium"
	URL         string
	Method      string
	Payload     string
	Evidence    string // what changed in the response
	PoC         string // exact curl command to reproduce
	Description string
}

// BizLogicResult holds all findings from a scan
type BizLogicResult struct {
	Target   string
	Findings []Finding
	Tested   int // number of test cases run
}

// StatusCallback is called for live progress updates
type StatusCallback func(test, status string)

// httpClient with no SSL verification (bug bounty targets often have cert issues)
var client = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// ─── Test Payloads ────────────────────────────────────────────────────────────

// pricePayloads — negative, zero, overflow, float tricks
var pricePayloads = []string{
	"-1", "-0.01", "-999", "0", "0.001", "0.00",
	"99999999", "-99999999",
	"1e-10", "1.0e308",
	"null", "undefined", "NaN", "Infinity",
}

// quantityPayloads — negative quantities, overflow
var quantityPayloads = []string{
	"-1", "-100", "-9999",
	"0", "99999999",
	"1.5", "-1.5",
	"null", "undefined",
}

// idorPayloads — sequential IDs to test IDOR
var idorOffsets = []int{-2, -1, 1, 2, 100, 1000}

// couponPayloads — coupon/promo code abuse
var couponPayloads = []string{
	"ADMIN", "FREE", "100OFF", "DISCOUNT100",
	"TEST", "DEBUG", "INTERNAL",
	"' OR '1'='1", "1; DROP TABLE coupons--",
}

// workflowBypassPayloads — skip payment/verification steps
var workflowBypassPayloads = []struct {
	param string
	value string
}{
	{"status", "paid"},
	{"status", "verified"},
	{"status", "approved"},
	{"payment_status", "completed"},
	{"is_paid", "true"},
	{"is_verified", "true"},
	{"step", "complete"},
	{"verified", "1"},
	{"admin", "true"},
	{"role", "admin"},
	{"is_admin", "true"},
	{"premium", "true"},
}

// ─── Main Scanner ─────────────────────────────────────────────────────────────

// RunBizLogicScan runs all business logic tests against the target
func RunBizLogicScan(target string, cookies, headers map[string]string, progress StatusCallback) BizLogicResult {
	result := BizLogicResult{Target: target}

	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// ── Phase 1: Discover endpoints ──────────────────────────────────────
	progress("discovery", "Discovering API endpoints...")
	endpoints := discoverEndpoints(target, cookies, headers)
	progress("discovery", fmt.Sprintf("Found %d endpoints to test", len(endpoints)))

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 10 concurrent tests

	// ── Phase 2: Run all test suites ─────────────────────────────────────
	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			findings := []Finding{}

			// Test 1: Price manipulation
			if ep.HasPriceParam {
				f := testPriceManipulation(ep, cookies, headers)
				findings = append(findings, f...)
				result.Tested += len(pricePayloads)
			}

			// Test 2: Quantity manipulation
			if ep.HasQuantityParam {
				f := testQuantityManipulation(ep, cookies, headers)
				findings = append(findings, f...)
				result.Tested += len(quantityPayloads)
			}

			// Test 3: IDOR
			if ep.HasIDParam {
				f := testIDOR(ep, cookies, headers)
				findings = append(findings, f...)
				result.Tested += len(idorOffsets)
			}

			// Test 4: Workflow bypass
			f := testWorkflowBypass(ep, cookies, headers)
			findings = append(findings, f...)
			result.Tested += len(workflowBypassPayloads)

			// Test 5: Race condition
			if ep.Method == "POST" {
				f := testRaceCondition(ep, cookies, headers)
				findings = append(findings, f...)
				result.Tested++
			}

			// Test 6: Coupon/promo abuse
			if ep.HasCouponParam {
				f := testCouponAbuse(ep, cookies, headers)
				findings = append(findings, f...)
				result.Tested += len(couponPayloads)
			}

			// Test 7: Mass assignment
			f2 := testMassAssignment(ep, cookies, headers)
			findings = append(findings, f2...)
			result.Tested++

			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				for _, f := range findings {
					progress(f.Type, fmt.Sprintf("🐛 FOUND: [%s] %s — %s", f.Severity, f.Type, f.URL))
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return result
}

// ─── Endpoint Discovery ───────────────────────────────────────────────────────

// Endpoint represents a discovered API endpoint
type Endpoint struct {
	URL             string
	Method          string
	Params          map[string]string // param name → sample value
	HasPriceParam   bool
	HasQuantityParam bool
	HasIDParam      bool
	HasCouponParam  bool
	BaseResponse    string // baseline response for comparison
	BaseStatus      int
}

var priceParamRe = regexp.MustCompile(`(?i)(price|amount|cost|total|fee|charge|payment|value|sum)`)
var quantityParamRe = regexp.MustCompile(`(?i)(qty|quantity|count|num|number|units|items)`)
var idParamRe = regexp.MustCompile(`(?i)(id|user_id|account_id|order_id|product_id|item_id|uid|uuid)`)
var couponParamRe = regexp.MustCompile(`(?i)(coupon|promo|code|discount|voucher|referral)`)

func discoverEndpoints(target string, cookies, headers map[string]string) []Endpoint {
	var endpoints []Endpoint

	// Common API paths to probe
	commonPaths := []struct {
		path   string
		method string
		params map[string]string
	}{
		// E-commerce
		{"/api/cart", "POST", map[string]string{"product_id": "1", "quantity": "1", "price": "10.00"}},
		{"/api/cart/add", "POST", map[string]string{"item_id": "1", "qty": "1", "amount": "9.99"}},
		{"/api/order", "POST", map[string]string{"product_id": "1", "quantity": "1", "total": "10.00"}},
		{"/api/checkout", "POST", map[string]string{"amount": "10.00", "currency": "USD"}},
		{"/api/payment", "POST", map[string]string{"amount": "10.00", "status": "pending"}},
		{"/api/coupon/apply", "POST", map[string]string{"code": "TEST10", "order_id": "1"}},
		{"/api/promo", "POST", map[string]string{"promo_code": "SAVE10"}},
		// User management
		{"/api/user/profile", "GET", map[string]string{"user_id": "1"}},
		{"/api/user/1", "GET", map[string]string{}},
		{"/api/account", "GET", map[string]string{"id": "1"}},
		{"/api/users/1/orders", "GET", map[string]string{}},
		// Admin/privilege
		{"/api/admin", "GET", map[string]string{}},
		{"/api/admin/users", "GET", map[string]string{}},
		{"/api/upgrade", "POST", map[string]string{"plan": "premium", "user_id": "1"}},
		{"/api/subscription", "POST", map[string]string{"plan": "pro", "status": "active"}},
		// Transfer/financial
		{"/api/transfer", "POST", map[string]string{"amount": "100", "to": "user2", "from": "user1"}},
		{"/api/withdraw", "POST", map[string]string{"amount": "100"}},
		{"/api/redeem", "POST", map[string]string{"points": "100", "user_id": "1"}},
		// Verification bypass
		{"/api/verify", "POST", map[string]string{"token": "test", "status": "verified"}},
		{"/api/confirm", "POST", map[string]string{"order_id": "1", "status": "confirmed"}},
	}

	for _, cp := range commonPaths {
		url := target + cp.path
		// Quick probe to see if endpoint exists
		resp, err := doRequest(cp.method, url, cp.params, cookies, headers)
		if err != nil || resp.StatusCode == 404 || resp.StatusCode == 405 {
			continue
		}

		ep := Endpoint{
			URL:          url,
			Method:       cp.method,
			Params:       cp.params,
			BaseStatus:   resp.StatusCode,
			BaseResponse: resp.Body[:min(500, len(resp.Body))],
		}

		// Classify params
		for k := range cp.params {
			if priceParamRe.MatchString(k) {
				ep.HasPriceParam = true
			}
			if quantityParamRe.MatchString(k) {
				ep.HasQuantityParam = true
			}
			if idParamRe.MatchString(k) {
				ep.HasIDParam = true
			}
			if couponParamRe.MatchString(k) {
				ep.HasCouponParam = true
			}
		}

		endpoints = append(endpoints, ep)
	}

	return endpoints
}

// ─── Test Functions ───────────────────────────────────────────────────────────

func testPriceManipulation(ep Endpoint, cookies, headers map[string]string) []Finding {
	var findings []Finding

	for _, payload := range pricePayloads {
		params := copyParams(ep.Params)
		// Replace all price-like params with payload
		for k := range params {
			if priceParamRe.MatchString(k) {
				params[k] = payload
			}
		}

		resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
		if err != nil {
			continue
		}

		// Anomaly detection: success response with negative/zero price
		if isSuccessResponse(resp) && ep.BaseStatus >= 400 {
			findings = append(findings, Finding{
				Type:        "price_manipulation",
				Severity:    "critical",
				URL:         ep.URL,
				Method:      ep.Method,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Server accepted price=%s (status %d)", payload, resp.StatusCode),
				PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
				Description: fmt.Sprintf("Server accepted manipulated price value '%s'. Attacker can purchase items for free or negative amounts.", payload),
			})
		}

		// Check if response contains price confirmation with our manipulated value
		if strings.Contains(resp.Body, payload) && isSuccessResponse(resp) {
			val, _ := strconv.ParseFloat(payload, 64)
			if val <= 0 {
				findings = append(findings, Finding{
					Type:        "price_manipulation",
					Severity:    "critical",
					URL:         ep.URL,
					Method:      ep.Method,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Response reflects manipulated price: %s", payload),
					PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
					Description: "Server reflects and accepts negative/zero price in response.",
				})
			}
		}
	}

	return findings
}

func testQuantityManipulation(ep Endpoint, cookies, headers map[string]string) []Finding {
	var findings []Finding

	for _, payload := range quantityPayloads {
		params := copyParams(ep.Params)
		for k := range params {
			if quantityParamRe.MatchString(k) {
				params[k] = payload
			}
		}

		resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
		if err != nil {
			continue
		}

		val, parseErr := strconv.ParseFloat(payload, 64)
		if parseErr == nil && val < 0 && isSuccessResponse(resp) {
			findings = append(findings, Finding{
				Type:        "negative_quantity",
				Severity:    "high",
				URL:         ep.URL,
				Method:      ep.Method,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Server accepted negative quantity=%s (status %d)", payload, resp.StatusCode),
				PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
				Description: "Server accepts negative quantity. Attacker can reverse charges or get refunds without returning items.",
			})
		}
	}

	return findings
}

func testIDOR(ep Endpoint, cookies, headers map[string]string) []Finding {
	var findings []Finding

	// Get baseline with original ID
	baseResp, err := doRequest(ep.Method, ep.URL, ep.Params, cookies, headers)
	if err != nil || !isSuccessResponse(baseResp) {
		return nil
	}

	for k, v := range ep.Params {
		if !idParamRe.MatchString(k) {
			continue
		}

		baseID, err := strconv.Atoi(v)
		if err != nil {
			continue
		}

		for _, offset := range idorOffsets {
			newID := baseID + offset
			if newID <= 0 {
				continue
			}

			params := copyParams(ep.Params)
			params[k] = strconv.Itoa(newID)

			resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
			if err != nil {
				continue
			}

			// IDOR: different user's data returned successfully
			if isSuccessResponse(resp) && resp.Body != baseResp.Body && len(resp.Body) > 50 {
				// Check if response contains user data (email, name, etc.)
				if containsUserData(resp.Body) {
					findings = append(findings, Finding{
						Type:        "idor",
						Severity:    "high",
						URL:         ep.URL,
						Method:      ep.Method,
						Payload:     fmt.Sprintf("%s=%d", k, newID),
						Evidence:    fmt.Sprintf("Different user data returned for %s=%d (original=%d)", k, newID, baseID),
						PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
						Description: fmt.Sprintf("IDOR: Changing %s from %d to %d returns another user's data without authorization check.", k, baseID, newID),
					})
				}
			}
		}
	}

	return findings
}

func testWorkflowBypass(ep Endpoint, cookies, headers map[string]string) []Finding {
	var findings []Finding

	for _, bypass := range workflowBypassPayloads {
		params := copyParams(ep.Params)
		params[bypass.param] = bypass.value

		resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
		if err != nil {
			continue
		}

		// Bypass detected: server accepted privileged status
		if isSuccessResponse(resp) {
			// Check if response indicates elevated access
			lower := strings.ToLower(resp.Body)
			if strings.Contains(lower, "admin") || strings.Contains(lower, "premium") ||
				strings.Contains(lower, "verified") || strings.Contains(lower, "approved") ||
				strings.Contains(lower, "success") {
				// Only flag if baseline didn't have this
				baseResp, _ := doRequest(ep.Method, ep.URL, ep.Params, cookies, headers)
				if baseResp.Body != resp.Body {
					findings = append(findings, Finding{
						Type:        "workflow_bypass",
						Severity:    "high",
						URL:         ep.URL,
						Method:      ep.Method,
						Payload:     fmt.Sprintf("%s=%s", bypass.param, bypass.value),
						Evidence:    fmt.Sprintf("Server accepted %s=%s and returned different response", bypass.param, bypass.value),
						PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
						Description: fmt.Sprintf("Workflow bypass: Setting %s=%s bypasses server-side validation. Attacker can skip payment/verification steps.", bypass.param, bypass.value),
					})
				}
			}
		}
	}

	return findings
}

func testRaceCondition(ep Endpoint, cookies, headers map[string]string) []Finding {
	// Send 20 concurrent identical requests and check for duplicate processing
	const concurrency = 20
	responses := make([]httpResponse, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := doRequest(ep.Method, ep.URL, ep.Params, cookies, headers)
			if err == nil {
				responses[i] = resp
			}
		}()
	}
	wg.Wait()

	// Count success responses
	successCount := 0
	for _, r := range responses {
		if isSuccessResponse(r) {
			successCount++
		}
	}

	// Race condition: more than 1 success for a single-use operation
	if successCount > 1 {
		return []Finding{{
			Type:        "race_condition",
			Severity:    "high",
			URL:         ep.URL,
			Method:      ep.Method,
			Payload:     fmt.Sprintf("%d concurrent requests", concurrency),
			Evidence:    fmt.Sprintf("%d/%d requests succeeded (expected: 1)", successCount, concurrency),
			PoC:         fmt.Sprintf("# Send %d concurrent requests:\nfor i in $(seq 1 %d); do %s & done; wait", concurrency, concurrency, buildCurlPoC(ep.Method, ep.URL, ep.Params, cookies, headers)),
			Description: fmt.Sprintf("Race condition: %d concurrent requests all succeeded. Attacker can redeem coupons/rewards multiple times or bypass rate limits.", successCount),
		}}
	}

	return nil
}

func testCouponAbuse(ep Endpoint, cookies, headers map[string]string) []Finding {
	var findings []Finding

	for _, code := range couponPayloads {
		params := copyParams(ep.Params)
		for k := range params {
			if couponParamRe.MatchString(k) {
				params[k] = code
			}
		}

		resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
		if err != nil {
			continue
		}

		lower := strings.ToLower(resp.Body)
		if isSuccessResponse(resp) && (strings.Contains(lower, "discount") ||
			strings.Contains(lower, "applied") || strings.Contains(lower, "valid")) {
			findings = append(findings, Finding{
				Type:        "coupon_abuse",
				Severity:    "medium",
				URL:         ep.URL,
				Method:      ep.Method,
				Payload:     code,
				Evidence:    fmt.Sprintf("Coupon code '%s' accepted", code),
				PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
				Description: fmt.Sprintf("Coupon/promo code '%s' was accepted. Check if it can be applied multiple times or stacked.", code),
			})
		}
	}

	return findings
}

func testMassAssignment(ep Endpoint, cookies, headers map[string]string) []Finding {
	// Try injecting privileged fields that shouldn't be user-settable
	privilegedFields := map[string]string{
		"role":         "admin",
		"is_admin":     "true",
		"admin":        "1",
		"premium":      "true",
		"verified":     "true",
		"balance":      "99999",
		"credit":       "99999",
		"subscription": "enterprise",
		"plan":         "enterprise",
		"permissions":  "all",
	}

	params := copyParams(ep.Params)
	for k, v := range privilegedFields {
		params[k] = v
	}

	baseResp, _ := doRequest(ep.Method, ep.URL, ep.Params, cookies, headers)
	resp, err := doRequest(ep.Method, ep.URL, params, cookies, headers)
	if err != nil {
		return nil
	}

	if isSuccessResponse(resp) && resp.Body != baseResp.Body {
		lower := strings.ToLower(resp.Body)
		if strings.Contains(lower, "admin") || strings.Contains(lower, "premium") ||
			strings.Contains(lower, "enterprise") || strings.Contains(lower, "verified") {
			return []Finding{{
				Type:        "mass_assignment",
				Severity:    "critical",
				URL:         ep.URL,
				Method:      ep.Method,
				Payload:     "role=admin&is_admin=true&premium=true",
				Evidence:    "Response changed when privileged fields injected",
				PoC:         buildCurlPoC(ep.Method, ep.URL, params, cookies, headers),
				Description: "Mass assignment vulnerability: Server accepts and processes privileged fields (role, is_admin, premium) from user input without filtering.",
			}}
		}
	}

	return nil
}

// ─── HTTP Helpers ─────────────────────────────────────────────────────────────

type httpResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}

func doRequest(method, url string, params map[string]string, cookies, extraHeaders map[string]string) (httpResponse, error) {
	var req *http.Request
	var err error

	if method == "GET" {
		// Build query string
		parts := []string{}
		for k, v := range params {
			parts = append(parts, k+"="+v)
		}
		fullURL := url
		if len(parts) > 0 {
			fullURL += "?" + strings.Join(parts, "&")
		}
		req, err = http.NewRequest("GET", fullURL, nil)
	} else {
		// POST with JSON body
		body, _ := json.Marshal(params)
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if err != nil {
		return httpResponse{}, err
	}

	// Set headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json, text/html, */*")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	// Set cookies
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	resp, err := client.Do(req)
	if err != nil {
		return httpResponse{}, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024)) // 50KB max

	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	return httpResponse{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Headers:    respHeaders,
	}, nil
}

func isSuccessResponse(r httpResponse) bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func containsUserData(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "email") ||
		strings.Contains(lower, "username") ||
		strings.Contains(lower, "phone") ||
		strings.Contains(lower, "address") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret")
}

func copyParams(params map[string]string) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

func buildCurlPoC(method, url string, params map[string]string, cookies, headers map[string]string) string {
	var sb strings.Builder
	sb.WriteString("curl -sk -X " + method + " '" + url + "'")

	if method != "GET" {
		body, _ := json.Marshal(params)
		sb.WriteString(" -H 'Content-Type: application/json'")
		sb.WriteString(" -d '" + string(body) + "'")
	} else {
		parts := []string{}
		for k, v := range params {
			parts = append(parts, k+"="+v)
		}
		if len(parts) > 0 {
			sb.WriteString("?" + strings.Join(parts, "&"))
		}
	}

	for k, v := range headers {
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}

	cookieParts := []string{}
	for k, v := range cookies {
		cookieParts = append(cookieParts, k+"="+v)
	}
	if len(cookieParts) > 0 {
		sb.WriteString(" -H 'Cookie: " + strings.Join(cookieParts, "; ") + "'")
	}

	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Report Generation ────────────────────────────────────────────────────────

// GenerateReport creates a markdown report of all findings
func GenerateReport(result BizLogicResult) string {
	var sb strings.Builder

	sb.WriteString("# Business Logic Bug Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Tests Run:** %d\n", result.Tested))
	sb.WriteString(fmt.Sprintf("**Findings:** %d\n\n", len(result.Findings)))

	if len(result.Findings) == 0 {
		sb.WriteString("No business logic vulnerabilities detected.\n")
		return sb.String()
	}

	// Group by severity
	critical := []Finding{}
	high := []Finding{}
	medium := []Finding{}
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			critical = append(critical, f)
		case "high":
			high = append(high, f)
		default:
			medium = append(medium, f)
		}
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| CRITICAL | %d |\n", len(critical)))
	sb.WriteString(fmt.Sprintf("| HIGH | %d |\n", len(high)))
	sb.WriteString(fmt.Sprintf("| MEDIUM | %d |\n\n", len(medium)))

	sb.WriteString("## Findings\n\n")
	for i, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("### %d. %s [%s]\n\n", i+1, f.Type, strings.ToUpper(f.Severity)))
		sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n", f.URL))
		sb.WriteString(fmt.Sprintf("- **Method:** %s\n", f.Method))
		sb.WriteString(fmt.Sprintf("- **Payload:** `%s`\n\n", f.Payload))
		sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))
		sb.WriteString(fmt.Sprintf("**Evidence:** %s\n\n", f.Evidence))
		sb.WriteString("**PoC:**\n```bash\n" + f.PoC + "\n```\n\n---\n\n")
	}

	return sb.String()
}
