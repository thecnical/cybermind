package breach

import (
"bytes"
"encoding/json"
"fmt"
"io"
"net/http"
"net/url"
"os"
"os/exec"
"path/filepath"
"strings"
"sync"
"time"
)

// rapidAPIClient is a shared HTTP client for all RapidAPI calls
var rapidAPIClient = &http.Client{Timeout: 12 * time.Second}

// rapidAPIGet performs a GET request to a RapidAPI endpoint
func rapidAPIGet(endpoint, host string) ([]byte, error) {
key := GetRapidAPIKey()
if key == "" {
return nil, fmt.Errorf("RapidAPI key not set — run: cybermind /breach --setup")
}
req, err := http.NewRequest("GET", endpoint, nil)
if err != nil {
return nil, err
}
req.Header.Set("X-RapidAPI-Key", key)
req.Header.Set("X-RapidAPI-Host", host)
resp, err := rapidAPIClient.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()
if resp.StatusCode == 401 || resp.StatusCode == 403 {
return nil, fmt.Errorf("invalid RapidAPI key")
}
if resp.StatusCode == 429 {
return nil, fmt.Errorf("RapidAPI rate limit exceeded")
}
if resp.StatusCode != 200 {
return nil, fmt.Errorf("RapidAPI %s: status %d", host, resp.StatusCode)
}
return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// rapidAPIPost performs a POST request to a RapidAPI endpoint
func rapidAPIPost(endpoint, host, body string) ([]byte, error) {
key := GetRapidAPIKey()
if key == "" {
return nil, fmt.Errorf("RapidAPI key not set — run: cybermind /breach --setup")
}
req, err := http.NewRequest("POST", endpoint, strings.NewReader(body))
if err != nil {
return nil, err
}
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-RapidAPI-Key", key)
req.Header.Set("X-RapidAPI-Host", host)
resp, err := rapidAPIClient.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()
if resp.StatusCode == 401 || resp.StatusCode == 403 {
return nil, fmt.Errorf("invalid RapidAPI key")
}
if resp.StatusCode == 429 {
return nil, fmt.Errorf("RapidAPI rate limit exceeded")
}
if resp.StatusCode != 200 {
return nil, fmt.Errorf("RapidAPI %s: status %d", host, resp.StatusCode)
}
return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

// ─── 1. Social Media Scanner (osint-org) ─────────────────────────────────────

// SocialMediaResult holds results from social media account checks
type SocialMediaResult struct {
Platform string
Username string
Found    bool
URL      string
Error    string
}

// CheckSocialMediaScanner checks username across major platforms.
// Uses sherlock CLI if available (real), falls back to direct HTTP checks.
func CheckSocialMediaScanner(username string) ([]SocialMediaResult, error) {
	u := strings.TrimPrefix(username, "@")
	if strings.Contains(u, "@") {
		u = strings.Split(u, "@")[0]
	}
	if u == "" {
		return nil, fmt.Errorf("empty username")
	}

	// Try sherlock CLI first — real tool, installed on Kali
	if sherlockPath, err := exec.LookPath("sherlock"); err == nil {
		out, runErr := runSocialCmd(30, sherlockPath, u, "--print-found", "--timeout", "10", "--no-color")
		if runErr == nil && strings.TrimSpace(out) != "" {
			return parseSherlock(u, out), nil
		}
	}

	// Fallback: direct HTTP checks for top platforms (no API key needed)
	return checkPlatformsDirect(u), nil
}

// runSocialCmd runs a command with timeout for social media checks
func runSocialCmd(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = nil
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return out.String(), nil
	}
}

// parseSherlock parses sherlock output into SocialMediaResult slice
func parseSherlock(username, output string) []SocialMediaResult {
	var results []SocialMediaResult
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "[+]") && strings.Contains(line, "http") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				platform := strings.TrimSpace(strings.TrimPrefix(parts[0], "[+]"))
				profileURL := strings.TrimSpace(parts[1])
				if strings.HasPrefix(profileURL, "//") {
					profileURL = "https:" + profileURL
				}
				results = append(results, SocialMediaResult{
					Platform: platform,
					Username: username,
					Found:    true,
					URL:      profileURL,
				})
			}
		}
	}
	return results
}

// checkPlatformsDirect does direct HTTP GET checks for top platforms
func checkPlatformsDirect(username string) []SocialMediaResult {
	type platformCheck struct {
		name string
		url  string
	}
	platforms := []platformCheck{
		{"GitHub", fmt.Sprintf("https://github.com/%s", username)},
		{"Twitter/X", fmt.Sprintf("https://x.com/%s", username)},
		{"Instagram", fmt.Sprintf("https://www.instagram.com/%s/", username)},
		{"Reddit", fmt.Sprintf("https://www.reddit.com/user/%s", username)},
		{"TikTok", fmt.Sprintf("https://www.tiktok.com/@%s", username)},
		{"YouTube", fmt.Sprintf("https://www.youtube.com/@%s", username)},
		{"Twitch", fmt.Sprintf("https://www.twitch.tv/%s", username)},
		{"Pinterest", fmt.Sprintf("https://www.pinterest.com/%s/", username)},
		{"Medium", fmt.Sprintf("https://medium.com/@%s", username)},
		{"HackerOne", fmt.Sprintf("https://hackerone.com/%s", username)},
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	type checkResult struct {
		platform string
		purl     string
		found    bool
	}
	ch := make(chan checkResult, len(platforms))

	for _, p := range platforms {
		go func(pc platformCheck) {
			req, err := http.NewRequest("GET", pc.url, nil)
			if err != nil {
				ch <- checkResult{pc.name, pc.url, false}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
			resp, err := client.Do(req)
			if err != nil {
				ch <- checkResult{pc.name, pc.url, false}
				return
			}
			resp.Body.Close()
			found := resp.StatusCode == 200
			if resp.StatusCode == 302 || resp.StatusCode == 301 {
				loc := resp.Header.Get("Location")
				found = !strings.Contains(loc, "login") && !strings.Contains(loc, "404") && !strings.Contains(loc, "signup")
			}
			ch <- checkResult{pc.name, pc.url, found}
		}(p)
	}

	var results []SocialMediaResult
	for range platforms {
		r := <-ch
		results = append(results, SocialMediaResult{
			Platform: r.platform,
			Username: username,
			Found:    r.found,
			URL:      r.purl,
		})
	}
	return results
}


// CheckInstagram checks if email/username exists on Instagram
func CheckInstagram(target string) (bool, string, error) {
endpoint := fmt.Sprintf("https://instagram-checker.p.rapidapi.com/check?username=%s", url.QueryEscape(target))
body, err := rapidAPIGet(endpoint, "instagram-checker.p.rapidapi.com")
if err != nil {
return false, "", err
}
var raw map[string]interface{}
if json.Unmarshal(body, &raw) != nil {
return false, "", nil
}
found, _ := raw["found"].(bool)
profileURL, _ := raw["url"].(string)
return found, profileURL, nil
}

// CheckFacebook checks if email/username exists on Facebook
func CheckFacebook(target string) (bool, string, error) {
endpoint := fmt.Sprintf("https://facebook-checker.p.rapidapi.com/check?username=%s", url.QueryEscape(target))
body, err := rapidAPIGet(endpoint, "facebook-checker.p.rapidapi.com")
if err != nil {
return false, "", err
}
var raw map[string]interface{}
if json.Unmarshal(body, &raw) != nil {
return false, "", nil
}
found, _ := raw["found"].(bool)
profileURL, _ := raw["url"].(string)
return found, profileURL, nil
}

// CheckTwitterX checks if email/username exists on X (Twitter)
func CheckTwitterX(target string) (bool, string, error) {
endpoint := fmt.Sprintf("https://x-checker.p.rapidapi.com/check?username=%s", url.QueryEscape(target))
body, err := rapidAPIGet(endpoint, "x-checker.p.rapidapi.com")
if err != nil {
return false, "", err
}
var raw map[string]interface{}
if json.Unmarshal(body, &raw) != nil {
return false, "", nil
}
found, _ := raw["found"].(bool)
profileURL, _ := raw["url"].(string)
return found, profileURL, nil
}

// ─── 2. LeakInsight API (14B+ records) ───────────────────────────────────────

// LeakInsightResult holds breach data from LeakInsight
type LeakInsightResult struct {
Email    string
Password string
Hash     string
Source   string
Date     string
}

// CheckLeakInsight queries LeakInsight API for 14B+ breach records.
// Uses: leakinsight-api.p.rapidapi.com
func CheckLeakInsight(target string) ([]LeakInsightResult, error) {
endpoint := fmt.Sprintf("https://leakinsight-api.p.rapidapi.com/search?query=%s", url.QueryEscape(target))
body, err := rapidAPIGet(endpoint, "leakinsight-api.p.rapidapi.com")
if err != nil {
return nil, err
}

var raw struct {
Success bool `json:"success"`
Count   int  `json:"count"`
Results []struct {
Email    string `json:"email"`
Password string `json:"password"`
Hash     string `json:"hash"`
Source   string `json:"source"`
Date     string `json:"date"`
} `json:"results"`
}

if json.Unmarshal(body, &raw) != nil {
return nil, nil
}
if !raw.Success || raw.Count == 0 {
return nil, nil
}

var results []LeakInsightResult
for _, r := range raw.Results {
results = append(results, LeakInsightResult{
Email:    r.Email,
Password: r.Password,
Hash:     r.Hash,
Source:   r.Source,
Date:     r.Date,
})
}
return results, nil
}

// ─── 3. People Data Lookup (cloudcodes) ──────────────────────────────────────

// PeopleDataResult holds person lookup results
type PeopleDataResult struct {
Name     string
Phone    string
Email    string
Address  string
Social   []string
DeepWeb  string
Source   string
}

// CheckPeopleByPhone looks up person data by phone number.
// Uses: people-data-lookup.p.rapidapi.com
func CheckPeopleByPhone(phone string) (*PeopleDataResult, error) {
clean := strings.Map(func(r rune) rune {
if r >= '0' && r <= '9' || r == '+' {
return r
}
return -1
}, phone)

payload := fmt.Sprintf(`{"key":"$2b$10$6Pjg05c2CHnOQDHfe","value":"%s","lookupId":4}`, clean)
body, err := rapidAPIPost("https://people-data-lookup.p.rapidapi.com/api/developer/phone",
"people-data-lookup.p.rapidapi.com", payload)
if err != nil {
return nil, err
}

var resp struct {
RequestID string `json:"requestId"`
ID        int    `json:"id"`
Status    string `json:"status"`
}
if json.Unmarshal(body, &resp) != nil || resp.ID == 0 {
return nil, nil
}

// Poll for results
return pollPeopleDataResult(resp.ID)
}

// CheckPeopleByEmail looks up person data by email address.
func CheckPeopleByEmail(email string) (*PeopleDataResult, error) {
payload := fmt.Sprintf(`{"key":"$2b$10$6Pjg05c2CHnOQDHfe","value":"%s","lookupType":"email","lookupId":16}`, email)
body, err := rapidAPIPost("https://people-data-lookup.p.rapidapi.com/api/developer/deepweb",
"people-data-lookup.p.rapidapi.com", payload)
if err != nil {
return nil, err
}

var resp struct {
RequestID string `json:"requestId"`
ID        int    `json:"id"`
Status    string `json:"status"`
}
if json.Unmarshal(body, &resp) != nil || resp.ID == 0 {
return nil, nil
}

return pollPeopleDataResult(resp.ID)
}

// CheckPeopleDeepWeb searches dark web by email/phone/password/name.
func CheckPeopleDeepWeb(target, lookupType string) (*PeopleDataResult, error) {
payload := fmt.Sprintf(`{"key":"$2b$10$6Pjg05c2CHnOQDHfe","value":"%s","lookupType":"%s","lookupId":16}`,
target, lookupType)
body, err := rapidAPIPost("https://people-data-lookup.p.rapidapi.com/api/developer/deepweb",
"people-data-lookup.p.rapidapi.com", payload)
if err != nil {
return nil, err
}

var resp struct {
ID     int    `json:"id"`
Status string `json:"status"`
}
if json.Unmarshal(body, &resp) != nil || resp.ID == 0 {
return nil, nil
}

return pollPeopleDataResult(resp.ID)
}

// pollPeopleDataResult polls for async lookup results
func pollPeopleDataResult(id int) (*PeopleDataResult, error) {
key := GetRapidAPIKey()
if key == "" {
return nil, nil
}

// Poll up to 3 times with 2s delay
for i := 0; i < 3; i++ {
time.Sleep(2 * time.Second)
endpoint := fmt.Sprintf("https://people-data-lookup.p.rapidapi.com/api/request-monitor/api-usage/%d?key=$2b$10$6Pjg05c2CHnOQDHfe", id)
req, _ := http.NewRequest("GET", endpoint, nil)
req.Header.Set("X-RapidAPI-Key", key)
req.Header.Set("X-RapidAPI-Host", "people-data-lookup.p.rapidapi.com")

resp, err := rapidAPIClient.Do(req)
if err != nil {
continue
}
body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
resp.Body.Close()

var raw map[string]interface{}
if json.Unmarshal(body, &raw) != nil {
continue
}

status, _ := raw["status"].(string)
if status == "progress" {
continue
}

result := &PeopleDataResult{Source: "people-data-lookup"}
if name, ok := raw["name"].(string); ok {
result.Name = name
}
if phone, ok := raw["phone"].(string); ok {
result.Phone = phone
}
if email, ok := raw["email"].(string); ok {
result.Email = email
}
if addr, ok := raw["address"].(string); ok {
result.Address = addr
}
// Store raw response for AI analysis
result.DeepWeb = string(body)
return result, nil
}
return nil, nil
}

// ─── 4. IOC Search (Threat Intelligence) ─────────────────────────────────────

// IOCResult holds threat intelligence data
type IOCResult struct {
Indicator  string
Type       string // "hash" | "ip" | "domain" | "url"
Malicious  bool
Score      float64
Vendors    []string
Tags       []string
LastSeen   string
Country    string
ASN        string
}

// CheckIOC queries IOC Search API for threat intelligence.
// Supports: MD5/SHA1/SHA256 hashes, IPs, domains, URLs
// Uses: ioc-search.p.rapidapi.com
func CheckIOC(indicator string) (*IOCResult, error) {
iocType := detectIOCType(indicator)
endpoint := fmt.Sprintf("https://ioc-search.p.rapidapi.com/search?query=%s&type=%s",
url.QueryEscape(indicator), iocType)

body, err := rapidAPIGet(endpoint, "ioc-search.p.rapidapi.com")
if err != nil {
return nil, err
}

var raw map[string]interface{}
if json.Unmarshal(body, &raw) != nil {
return nil, nil
}

result := &IOCResult{Indicator: indicator, Type: iocType}

if malicious, ok := raw["malicious"].(bool); ok {
result.Malicious = malicious
}
if score, ok := raw["score"].(float64); ok {
result.Score = score
}
if country, ok := raw["country"].(string); ok {
result.Country = country
}
if asn, ok := raw["asn"].(string); ok {
result.ASN = asn
}
if lastSeen, ok := raw["last_seen"].(string); ok {
result.LastSeen = lastSeen
}
if vendors, ok := raw["vendors"].([]interface{}); ok {
for _, v := range vendors {
if s, ok := v.(string); ok {
result.Vendors = append(result.Vendors, s)
}
}
}
if tags, ok := raw["tags"].([]interface{}); ok {
for _, t := range tags {
if s, ok := t.(string); ok {
result.Tags = append(result.Tags, s)
}
}
}

return result, nil
}

func detectIOCType(indicator string) string {
// Hash detection
if len(indicator) == 32 || len(indicator) == 40 || len(indicator) == 64 {
allHex := true
for _, c := range indicator {
if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
allHex = false
break
}
}
if allHex {
return "hash"
}
}
// IP detection
parts := strings.Split(indicator, ".")
if len(parts) == 4 {
return "ip"
}
// URL detection
if strings.HasPrefix(indicator, "http://") || strings.HasPrefix(indicator, "https://") {
return "url"
}
return "domain"
}

// ─── 5. AbuseIPDB (Free — no RapidAPI key needed) ────────────────────────────

// AbuseIPDBResult holds IP reputation data
type AbuseIPDBResult struct {
IP           string
AbuseScore   int
Country      string
ISP          string
Domain       string
TotalReports int
LastReported string
IsWhitelisted bool
}

// CheckAbuseIPDB queries AbuseIPDB for IP reputation (free, 1000/day).
// No RapidAPI key needed — uses direct API.
func CheckAbuseIPDB(ip string) (*AbuseIPDBResult, error) {
abuseKey := getAbuseIPDBKey()

var req *http.Request
var err error

if abuseKey != "" {
reqURL := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose",
url.QueryEscape(ip))
req, err = http.NewRequest("GET", reqURL, nil)
if err != nil {
return nil, err
}
req.Header.Set("Key", abuseKey)
req.Header.Set("Accept", "application/json")
} else {
// Free tier via public endpoint
reqURL := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90",
url.QueryEscape(ip))
req, err = http.NewRequest("GET", reqURL, nil)
if err != nil {
return nil, err
}
req.Header.Set("Accept", "application/json")
}

client := &http.Client{Timeout: 8 * time.Second}
resp, err := client.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

if resp.StatusCode != 200 {
return nil, fmt.Errorf("AbuseIPDB: %d", resp.StatusCode)
}

body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))

var raw struct {
Data struct {
IPAddress            string `json:"ipAddress"`
AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
CountryCode          string `json:"countryCode"`
ISP                  string `json:"isp"`
Domain               string `json:"domain"`
TotalReports         int    `json:"totalReports"`
LastReportedAt       string `json:"lastReportedAt"`
IsWhitelisted        bool   `json:"isWhitelisted"`
} `json:"data"`
}

if json.Unmarshal(body, &raw) != nil {
return nil, nil
}

return &AbuseIPDBResult{
IP:            raw.Data.IPAddress,
AbuseScore:    raw.Data.AbuseConfidenceScore,
Country:       raw.Data.CountryCode,
ISP:           raw.Data.ISP,
Domain:        raw.Data.Domain,
TotalReports:  raw.Data.TotalReports,
LastReported:  raw.Data.LastReportedAt,
IsWhitelisted: raw.Data.IsWhitelisted,
}, nil
}

func getAbuseIPDBKey() string {
return getEnvOrConfig("ABUSEIPDB_API_KEY", "abuseipdb_key")
}

// ─── 6. VirusTotal (Free — 500/day) ──────────────────────────────────────────

// VirusTotalResult holds scan results
type VirusTotalResult struct {
Indicator   string
Type        string
Malicious   int
Suspicious  int
Harmless    int
Undetected  int
TotalVendors int
Permalink   string
Tags        []string
}

// CheckVirusTotal queries VirusTotal for file hash, URL, IP, or domain.
// Free tier: 500 requests/day. Key stored as VIRUSTOTAL_API_KEY env var.
func CheckVirusTotal(indicator string) (*VirusTotalResult, error) {
vtKey := getVirusTotalKey()
if vtKey == "" {
return nil, fmt.Errorf("VirusTotal API key not set — export VIRUSTOTAL_API_KEY=your_key")
}

iocType := detectIOCType(indicator)
var endpoint string
switch iocType {
case "hash":
endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", indicator)
case "ip":
endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", indicator)
case "url":
// URL needs to be base64url encoded
encoded := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(
encodeBase64([]byte(indicator))), "=")
endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/urls/%s", encoded)
default:
endpoint = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", indicator)
}

req, err := http.NewRequest("GET", endpoint, nil)
if err != nil {
return nil, err
}
req.Header.Set("x-apikey", vtKey)

client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

if resp.StatusCode == 404 {
return &VirusTotalResult{Indicator: indicator, Type: iocType}, nil
}
if resp.StatusCode != 200 {
return nil, fmt.Errorf("VirusTotal: %d", resp.StatusCode)
}

body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

var raw struct {
Data struct {
Attributes struct {
LastAnalysisStats struct {
Malicious  int `json:"malicious"`
Suspicious int `json:"suspicious"`
Harmless   int `json:"harmless"`
Undetected int `json:"undetected"`
} `json:"last_analysis_stats"`
Tags      []string `json:"tags"`
Permalink string   `json:"permalink"`
} `json:"attributes"`
} `json:"data"`
}

if json.Unmarshal(body, &raw) != nil {
return nil, nil
}

stats := raw.Data.Attributes.LastAnalysisStats
total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

return &VirusTotalResult{
Indicator:    indicator,
Type:         iocType,
Malicious:    stats.Malicious,
Suspicious:   stats.Suspicious,
Harmless:     stats.Harmless,
Undetected:   stats.Undetected,
TotalVendors: total,
Tags:         raw.Data.Attributes.Tags,
Permalink:    raw.Data.Attributes.Permalink,
}, nil
}

func getVirusTotalKey() string {
return getEnvOrConfig("VIRUSTOTAL_API_KEY", "virustotal_key")
}

// ─── 7. AlienVault OTX (Free — unlimited) ────────────────────────────────────

// OTXResult holds AlienVault OTX threat intel
type OTXResult struct {
Indicator  string
Type       string
Pulses     int
Tags       []string
MalwareFamily string
Country    string
ASN        string
}

// CheckAlienVaultOTX queries AlienVault OTX for threat intelligence.
// Free, no key required for basic queries.
func CheckAlienVaultOTX(indicator string) (*OTXResult, error) {
iocType := detectIOCType(indicator)
var section string
switch iocType {
case "ip":
section = "IPv4"
case "domain":
section = "domain"
case "hash":
section = "file"
case "url":
section = "url"
default:
section = "domain"
}

endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/%s/%s/general",
section, url.PathEscape(indicator))

req, _ := http.NewRequest("GET", endpoint, nil)
req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

otxKey := getEnvOrConfig("OTX_API_KEY", "otx_key")
if otxKey != "" {
req.Header.Set("X-OTX-API-KEY", otxKey)
}

client := &http.Client{Timeout: 8 * time.Second}
resp, err := client.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

if resp.StatusCode != 200 {
return nil, fmt.Errorf("OTX: %d", resp.StatusCode)
}

body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))

var raw struct {
PulseInfo struct {
Count  int `json:"count"`
Pulses []struct {
Tags         []string `json:"tags"`
MalwareFamilies []struct {
DisplayName string `json:"display_name"`
} `json:"malware_families"`
} `json:"pulses"`
} `json:"pulse_info"`
Country string `json:"country_name"`
ASN     string `json:"asn"`
}

if json.Unmarshal(body, &raw) != nil {
return nil, nil
}

result := &OTXResult{
Indicator: indicator,
Type:      iocType,
Pulses:    raw.PulseInfo.Count,
Country:   raw.Country,
ASN:       raw.ASN,
}

// Collect tags from all pulses
seen := map[string]bool{}
for _, pulse := range raw.PulseInfo.Pulses {
for _, tag := range pulse.Tags {
if !seen[tag] {
seen[tag] = true
result.Tags = append(result.Tags, tag)
}
}
for _, mf := range pulse.MalwareFamilies {
if result.MalwareFamily == "" {
result.MalwareFamily = mf.DisplayName
}
}
}

return result, nil
}

// ─── 8. URLScan.io (Free) ─────────────────────────────────────────────────────

// URLScanResult holds URL scan results
type URLScanResult struct {
URL        string
Domain     string
IP         string
Country    string
Malicious  bool
Score      int
Screenshot string
Tags       []string
ScanID     string
}

// CheckURLScan submits a URL to urlscan.io and returns results.
// Free, no key required for public scans.
func CheckURLScan(targetURL string) (*URLScanResult, error) {
urlscanKey := getEnvOrConfig("URLSCAN_API_KEY", "urlscan_key")

// Submit scan
payload := fmt.Sprintf(`{"url":"%s","visibility":"public"}`, targetURL)
req, _ := http.NewRequest("POST", "https://urlscan.io/api/v1/scan/", strings.NewReader(payload))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
if urlscanKey != "" {
req.Header.Set("API-Key", urlscanKey)
}

client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

if resp.StatusCode != 200 {
return nil, fmt.Errorf("URLScan submit: %d", resp.StatusCode)
}

body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
var submitResp struct {
UUID    string `json:"uuid"`
Message string `json:"message"`
}
if json.Unmarshal(body, &submitResp) != nil || submitResp.UUID == "" {
return nil, nil
}

// Wait for scan to complete (30s max)
time.Sleep(10 * time.Second)
for i := 0; i < 4; i++ {
resultURL := fmt.Sprintf("https://urlscan.io/api/v1/result/%s/", submitResp.UUID)
req2, _ := http.NewRequest("GET", resultURL, nil)
req2.Header.Set("User-Agent", "CyberMind-OSINT/1.0")

resp2, err := client.Do(req2)
if err != nil {
time.Sleep(5 * time.Second)
continue
}
if resp2.StatusCode == 404 {
resp2.Body.Close()
time.Sleep(5 * time.Second)
continue
}

body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 32*1024))
resp2.Body.Close()

var raw struct {
Page struct {
URL     string `json:"url"`
Domain  string `json:"domain"`
IP      string `json:"ip"`
Country string `json:"country"`
} `json:"page"`
Verdicts struct {
Overall struct {
Score     int  `json:"score"`
Malicious bool `json:"malicious"`
Tags      []string `json:"tags"`
} `json:"overall"`
} `json:"verdicts"`
Screenshot string `json:"screenshot"`
}

if json.Unmarshal(body2, &raw) == nil {
return &URLScanResult{
URL:        raw.Page.URL,
Domain:     raw.Page.Domain,
IP:         raw.Page.IP,
Country:    raw.Page.Country,
Malicious:  raw.Verdicts.Overall.Malicious,
Score:      raw.Verdicts.Overall.Score,
Tags:       raw.Verdicts.Overall.Tags,
Screenshot: raw.Screenshot,
ScanID:     submitResp.UUID,
}, nil
}
time.Sleep(5 * time.Second)
}
return nil, nil
}

// ─── 9. GreyNoise (Free tier) ─────────────────────────────────────────────────

// GreyNoiseResult holds GreyNoise IP classification
type GreyNoiseResult struct {
IP          string
Noise       bool   // is this IP scanning the internet?
Riot        bool   // is this a known benign service?
Name        string // company/service name if riot
Classification string // "malicious" | "benign" | "unknown"
LastSeen    string
Tags        []string
}

// CheckGreyNoise queries GreyNoise for IP classification.
// Free community API: 1000/day
func CheckGreyNoise(ip string) (*GreyNoiseResult, error) {
gnKey := getEnvOrConfig("GREYNOISE_API_KEY", "greynoise_key")

endpoint := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
req, _ := http.NewRequest("GET", endpoint, nil)
req.Header.Set("User-Agent", "CyberMind-OSINT/1.0")
if gnKey != "" {
req.Header.Set("key", gnKey)
}

client := &http.Client{Timeout: 8 * time.Second}
resp, err := client.Do(req)
if err != nil {
return nil, err
}
defer resp.Body.Close()

if resp.StatusCode == 404 {
return &GreyNoiseResult{IP: ip, Classification: "unknown"}, nil
}
if resp.StatusCode != 200 {
return nil, fmt.Errorf("GreyNoise: %d", resp.StatusCode)
}

body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))

var raw struct {
IP             string `json:"ip"`
Noise          bool   `json:"noise"`
Riot           bool   `json:"riot"`
Name           string `json:"name"`
Classification string `json:"classification"`
LastSeen       string `json:"last_seen"`
Message        string `json:"message"`
}

if json.Unmarshal(body, &raw) != nil {
return nil, nil
}

return &GreyNoiseResult{
IP:             raw.IP,
Noise:          raw.Noise,
Riot:           raw.Riot,
Name:           raw.Name,
Classification: raw.Classification,
LastSeen:       raw.LastSeen,
}, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// getEnvOrConfig gets a value from env var or config file
func getEnvOrConfig(envKey, configKey string) string {
if v := getEnvVar(envKey); v != "" {
return v
}
return getConfigValue(configKey)
}

func getEnvVar(key string) string {
	return os.Getenv(key)
}

func getConfigValue(key string) string {
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(filepath.Join(home, ".cybermind", "config.json"))
	if err != nil {
		return ""
	}
	var cfg map[string]interface{}
	if json.Unmarshal(data, &cfg) == nil {
		if v, ok := cfg[key].(string); ok {
			return v
		}
	}
	return ""
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(data []byte) string {
const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
var result strings.Builder
for i := 0; i < len(data); i += 3 {
b0 := data[i]
var b1, b2 byte
if i+1 < len(data) {
b1 = data[i+1]
}
if i+2 < len(data) {
b2 = data[i+2]
}
result.WriteByte(chars[b0>>2])
result.WriteByte(chars[((b0&3)<<4)|(b1>>4)])
if i+1 < len(data) {
result.WriteByte(chars[((b1&15)<<2)|(b2>>6)])
} else {
result.WriteByte('=')
}
if i+2 < len(data) {
result.WriteByte(chars[b2&63])
} else {
result.WriteByte('=')
}
}
return result.String()
}

// ─── 10. Threat Intel Aggregator ─────────────────────────────────────────────

// ThreatIntelReport aggregates results from all threat intel sources.
type ThreatIntelReport struct {
	Target       string
	IOC          *IOCResult
	AbuseIP      *AbuseIPDBResult
	VirusTotal   *VirusTotalResult
	OTX          *OTXResult
	URLScan      *URLScanResult
	GreyNoise    *GreyNoiseResult
	OverallScore int    // 0-100
	Verdict      string // "clean" | "suspicious" | "malicious"
}

// CheckAllThreatIntel runs all threat intel sources concurrently and returns an aggregated report.
func CheckAllThreatIntel(target string) *ThreatIntelReport {
	report := &ThreatIntelReport{Target: target}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(6)

	go func() {
		defer wg.Done()
		r, _ := CheckIOC(target)
		mu.Lock()
		report.IOC = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		iocType := detectIOCType(target)
		if iocType == "ip" {
			r, _ := CheckAbuseIPDB(target)
			mu.Lock()
			report.AbuseIP = r
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		r, _ := CheckVirusTotal(target)
		mu.Lock()
		report.VirusTotal = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r, _ := CheckAlienVaultOTX(target)
		mu.Lock()
		report.OTX = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		iocType := detectIOCType(target)
		if iocType == "url" || iocType == "domain" {
			r, _ := CheckURLScan(target)
			mu.Lock()
			report.URLScan = r
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		iocType := detectIOCType(target)
		if iocType == "ip" {
			r, _ := CheckGreyNoise(target)
			mu.Lock()
			report.GreyNoise = r
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Calculate overall score (0-100)
	score := 0

	if report.IOC != nil && report.IOC.Malicious {
		score += 40
	}
	if report.AbuseIP != nil {
		score += report.AbuseIP.AbuseScore / 3
	}
	if report.VirusTotal != nil && report.VirusTotal.TotalVendors > 0 {
		vtScore := (report.VirusTotal.Malicious * 100) / report.VirusTotal.TotalVendors
		score += vtScore / 2
	}
	if report.OTX != nil && report.OTX.Pulses > 0 {
		otxScore := report.OTX.Pulses * 5
		if otxScore > 30 {
			otxScore = 30
		}
		score += otxScore
	}
	if report.URLScan != nil && report.URLScan.Malicious {
		score += 25
	}
	if report.GreyNoise != nil && report.GreyNoise.Classification == "malicious" {
		score += 30
	}

	if score > 100 {
		score = 100
	}
	report.OverallScore = score

	switch {
	case score >= 60:
		report.Verdict = "malicious"
	case score >= 25:
		report.Verdict = "suspicious"
	default:
		report.Verdict = "clean"
	}

	return report
}