// Package brain - Structured Tool Output Parsers
// Replaces regex-based extraction with proper parsers for each tool.
package brain

import (
"encoding/json"
"fmt"
"regexp"
"strconv"
"strings"
"time"
)

// ─── Common Types ─────────────────────────────────────────────────────────────

// ParsedFinding is a normalized finding from any tool.
type ParsedFinding struct {
Tool        string
Type        string
Severity    string
Target      string
URL         string
Port        int
Service     string
CVE         string
CVSS        float64
Title       string
Description string
Evidence    string
Request     string
Response    string
PoC         string
Tags        []string
Timestamp   time.Time
}

// ─── Nuclei Parser ────────────────────────────────────────────────────────────

// NucleiJSONLine is one line of nuclei -json output.
type NucleiJSONLine struct {
TemplateID   string   `json:"template-id"`
TemplatePath string   `json:"template-path"`
Info         struct {
Name        string   `json:"name"`
Severity    string   `json:"severity"`
Description string   `json:"description"`
Tags        []string `json:"tags"`
Reference   []string `json:"reference"`
CVE         string   `json:"cve-id"`
CVSS        float64  `json:"cvss-score"`
} `json:"info"`
Type          string `json:"type"`
Host          string `json:"host"`
Matched       string `json:"matched-at"`
ExtractedResults []string `json:"extracted-results"`
Request       string `json:"request"`
Response      string `json:"response"`
IP            string `json:"ip"`
Timestamp     string `json:"timestamp"`
CURLCommand   string `json:"curl-command"`
}

// ParseNucleiOutput parses nuclei JSON output (one JSON object per line).
func ParseNucleiOutput(raw string) []ParsedFinding {
var findings []ParsedFinding
lines := strings.Split(strings.TrimSpace(raw), "\n")

for _, line := range lines {
line = strings.TrimSpace(line)
if line == "" || !strings.HasPrefix(line, "{") {
continue
}

var n NucleiJSONLine
if err := json.Unmarshal([]byte(line), &n); err != nil {
// Fallback: try to extract from non-JSON nuclei output
if f := parseNucleiTextLine(line); f != nil {
findings = append(findings, *f)
}
continue
}

ts, _ := time.Parse(time.RFC3339, n.Timestamp)
if ts.IsZero() {
ts = time.Now()
}

f := ParsedFinding{
Tool:        "nuclei",
Type:        n.Type,
Severity:    normalizeSeverityStr(n.Info.Severity),
Target:      n.Host,
URL:         n.Matched,
CVE:         n.Info.CVE,
CVSS:        n.Info.CVSS,
Title:       n.Info.Name,
Description: n.Info.Description,
Request:     truncate(n.Request, 2000),
Response:    truncate(n.Response, 1000),
PoC:         n.CURLCommand,
Tags:        n.Info.Tags,
Timestamp:   ts,
}

if len(n.ExtractedResults) > 0 {
f.Evidence = strings.Join(n.ExtractedResults, " | ")
}

findings = append(findings, f)
}

return findings
}

// parseNucleiTextLine handles non-JSON nuclei output like:
// [critical] [http] [CVE-2021-44228] target.com:8080
var nucleiTextRe = regexp.MustCompile(`\[(\w+)\]\s+\[(\w+)\]\s+(?:\[([^\]]+)\]\s+)?(.+)`)

func parseNucleiTextLine(line string) *ParsedFinding {
m := nucleiTextRe.FindStringSubmatch(line)
if m == nil {
return nil
}
return &ParsedFinding{
Tool:      "nuclei",
Severity:  normalizeSeverityStr(m[1]),
Type:      m[2],
CVE:       m[3],
Target:    strings.TrimSpace(m[4]),
Title:     strings.TrimSpace(m[4]),
Timestamp: time.Now(),
}
}

// ─── SQLMap Parser ────────────────────────────────────────────────────────────

// ParseSQLMapOutput parses sqlmap verbose output into structured findings.
func ParseSQLMapOutput(raw string) []ParsedFinding {
var findings []ParsedFinding

// Detect injection points
injectionRe := regexp.MustCompile(`(?i)Parameter:\s+(.+?)\s+\((.+?)\)\s*\n\s+Type:\s+(.+?)\s*\n\s+Title:\s+(.+?)\s*\n\s+Payload:\s+(.+?)(?:\n|$)`)
matches := injectionRe.FindAllStringSubmatch(raw, -1)

for _, m := range matches {
findings = append(findings, ParsedFinding{
Tool:        "sqlmap",
Type:        "sql_injection",
Severity:    "critical",
Title:       fmt.Sprintf("SQL Injection: %s", m[4]),
Description: fmt.Sprintf("Parameter: %s (%s)\nType: %s\nPayload: %s", m[1], m[2], m[3], m[5]),
Evidence:    fmt.Sprintf("Injection type: %s | Payload: %s", m[3], m[5]),
PoC:         extractSQLMapPoC(raw),
Timestamp:   time.Now(),
})
}

// Detect database info
dbRe := regexp.MustCompile(`(?i)back-end DBMS:\s+(.+)`)
if dbMatch := dbRe.FindStringSubmatch(raw); dbMatch != nil {
for i := range findings {
findings[i].Description += "\nDBMS: " + strings.TrimSpace(dbMatch[1])
}
}

// Detect extracted data
tableRe := regexp.MustCompile(`(?i)\[INFO\] fetching tables for database:\s+'(.+?)'`)
tableMatches := tableRe.FindAllStringSubmatch(raw, -1)
for _, tm := range tableMatches {
for i := range findings {
findings[i].Evidence += " | DB: " + tm[1]
}
}

// If no structured findings but sqlmap confirmed injection
if len(findings) == 0 && strings.Contains(strings.ToLower(raw), "is vulnerable") {
urlRe := regexp.MustCompile(`(?i)testing URL '(.+?)'`)
url := ""
if um := urlRe.FindStringSubmatch(raw); um != nil {
url = um[1]
}
findings = append(findings, ParsedFinding{
Tool:      "sqlmap",
Type:      "sql_injection",
Severity:  "critical",
Title:     "SQL Injection Confirmed",
URL:       url,
Evidence:  "sqlmap confirmed injection (see raw output for details)",
Timestamp: time.Now(),
})
}

return findings
}

func extractSQLMapPoC(raw string) string {
pocRe := regexp.MustCompile(`(?i)Payload:\s+(.+?)(?:\n|$)`)
if m := pocRe.FindStringSubmatch(raw); m != nil {
return "sqlmap payload: " + strings.TrimSpace(m[1])
}
return ""
}

// ─── Dalfox Parser ────────────────────────────────────────────────────────────

// ParseDalfoxOutput parses dalfox output into structured XSS findings.
func ParseDalfoxOutput(raw string) []ParsedFinding {
var findings []ParsedFinding

// Dalfox JSON output
if strings.Contains(raw, `"type":"V"`) || strings.Contains(raw, `"type":"G"`) {
lines := strings.Split(raw, "\n")
for _, line := range lines {
line = strings.TrimSpace(line)
if !strings.HasPrefix(line, "{") {
continue
}
var obj map[string]interface{}
if err := json.Unmarshal([]byte(line), &obj); err != nil {
continue
}
findingType, _ := obj["type"].(string)
if findingType != "V" && findingType != "G" {
continue
}
url, _ := obj["data"].(string)
param, _ := obj["param"].(string)
payload, _ := obj["payload"].(string)
sev := "medium"
if findingType == "V" {
sev = "high"
}
findings = append(findings, ParsedFinding{
Tool:      "dalfox",
Type:      "xss",
Severity:  sev,
URL:       url,
Title:     fmt.Sprintf("XSS in parameter: %s", param),
Evidence:  fmt.Sprintf("Payload: %s", payload),
PoC:       fmt.Sprintf("curl '%s'", url),
Timestamp: time.Now(),
})
}
return findings
}

// Text output fallback
// [V] Verified XSS
verifiedRe := regexp.MustCompile(`(?i)\[V\]\s+(.+?)(?:\n|$)`)
for _, m := range verifiedRe.FindAllStringSubmatch(raw, -1) {
findings = append(findings, ParsedFinding{
Tool:      "dalfox",
Type:      "xss",
Severity:  "high",
Title:     "Verified XSS",
URL:       strings.TrimSpace(m[1]),
Evidence:  strings.TrimSpace(m[1]),
Timestamp: time.Now(),
})
}

// [G] Grep-based (potential)
grepRe := regexp.MustCompile(`(?i)\[G\]\s+(.+?)(?:\n|$)`)
for _, m := range grepRe.FindAllStringSubmatch(raw, -1) {
findings = append(findings, ParsedFinding{
Tool:      "dalfox",
Type:      "xss_potential",
Severity:  "medium",
Title:     "Potential XSS (unverified)",
URL:       strings.TrimSpace(m[1]),
Evidence:  strings.TrimSpace(m[1]),
Timestamp: time.Now(),
})
}

return findings
}

// ─── Nmap Parser ─────────────────────────────────────────────────────────────

// NmapPort represents a parsed nmap port entry.
type NmapPort struct {
Port     int
Protocol string
State    string
Service  string
Version  string
Scripts  []string
}

// ParseNmapOutput parses nmap text output into structured port data.
func ParseNmapOutput(raw string) ([]NmapPort, []ParsedFinding) {
var ports []NmapPort
var findings []ParsedFinding

// Parse port lines: 80/tcp   open  http    Apache httpd 2.4.41
portRe := regexp.MustCompile(`(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)`)
for _, m := range portRe.FindAllStringSubmatch(raw, -1) {
portNum, _ := strconv.Atoi(m[1])
p := NmapPort{
Port:     portNum,
Protocol: m[2],
State:    m[3],
Service:  m[4],
Version:  strings.TrimSpace(m[5]),
}
ports = append(ports, p)
}

// Parse script output for vulnerabilities
// |_vuln: CVE-2021-44228 ...
vulnRe := regexp.MustCompile(`(?i)\|\s*(?:_)?vuln[^:]*:\s*(.+?)(?:\n|$)`)
for _, m := range vulnRe.FindAllStringSubmatch(raw, -1) {
desc := strings.TrimSpace(m[1])
cve := extractCVE(desc)
findings = append(findings, ParsedFinding{
Tool:        "nmap",
Type:        "vulnerability",
Severity:    "high",
Title:       desc,
CVE:         cve,
Description: desc,
Timestamp:   time.Now(),
})
}

// Parse CVEs from script output
cveRe := regexp.MustCompile(`(CVE-\d{4}-\d{4,7})`)
for _, m := range cveRe.FindAllStringSubmatch(raw, -1) {
cve := m[1]
// Avoid duplicates
found := false
for _, f := range findings {
if f.CVE == cve {
found = true
break
}
}
if !found {
findings = append(findings, ParsedFinding{
Tool:      "nmap",
Type:      "cve",
Severity:  "high",
CVE:       cve,
Title:     "CVE detected: " + cve,
Timestamp: time.Now(),
})
}
}

return ports, findings
}

// ─── Subfinder / HTTPX Parser ─────────────────────────────────────────────────

// ParseSubfinderOutput parses subfinder output (one subdomain per line).
func ParseSubfinderOutput(raw string) []string {
var subdomains []string
seen := map[string]bool{}
for _, line := range strings.Split(raw, "\n") {
line = strings.TrimSpace(line)
if line == "" || strings.HasPrefix(line, "[") {
continue
}
if !seen[line] {
seen[line] = true
subdomains = append(subdomains, line)
}
}
return subdomains
}

// HTTPXResult is one line of httpx -json output.
type HTTPXResult struct {
URL          string   `json:"url"`
StatusCode   int      `json:"status-code"`
ContentType  string   `json:"content-type"`
Title        string   `json:"title"`
Technologies []string `json:"tech"`
WebServer    string   `json:"webserver"`
CDN          string   `json:"cdn"`
IP           string   `json:"host"`
Port         string   `json:"port"`
TLS          struct {
Subject string `json:"subject_cn"`
} `json:"tls"`
}

// ParseHTTPXOutput parses httpx JSON output.
func ParseHTTPXOutput(raw string) []HTTPXResult {
var results []HTTPXResult
for _, line := range strings.Split(raw, "\n") {
line = strings.TrimSpace(line)
if !strings.HasPrefix(line, "{") {
continue
}
var r HTTPXResult
if err := json.Unmarshal([]byte(line), &r); err == nil {
results = append(results, r)
}
}
return results
}

// ─── FFUF Parser ─────────────────────────────────────────────────────────────

// FFUFResult is one result from ffuf -json output.
type FFUFResult struct {
Input      map[string]string `json:"input"`
Position   int               `json:"position"`
Status     int               `json:"status"`
Length     int               `json:"length"`
Words      int               `json:"words"`
Lines      int               `json:"lines"`
ContentType string           `json:"content-type"`
Redirectlocation string      `json:"redirectlocation"`
URL        string            `json:"url"`
Duration   int64             `json:"duration"`
}

// FFUFOutput is the top-level ffuf JSON output.
type FFUFOutput struct {
Results []FFUFResult `json:"results"`
}

// ParseFFUFOutput parses ffuf JSON output.
func ParseFFUFOutput(raw string) []FFUFResult {
// Try full JSON object first
var out FFUFOutput
if err := json.Unmarshal([]byte(raw), &out); err == nil {
return out.Results
}

// Fallback: parse line by line
var results []FFUFResult
for _, line := range strings.Split(raw, "\n") {
line = strings.TrimSpace(line)
if !strings.HasPrefix(line, "{") {
continue
}
var r FFUFResult
if err := json.Unmarshal([]byte(line), &r); err == nil {
results = append(results, r)
}
}
return results
}

// ─── Aggregate Parser ─────────────────────────────────────────────────────────

// ParseToolOutput routes raw output to the correct parser based on tool name.
func ParseToolOutput(tool, raw string) []ParsedFinding {
switch strings.ToLower(tool) {
case "nuclei":
return ParseNucleiOutput(raw)
case "sqlmap":
return ParseSQLMapOutput(raw)
case "dalfox":
return ParseDalfoxOutput(raw)
case "nmap":
_, findings := ParseNmapOutput(raw)
return findings
default:
return nil
}
}

// DeduplicateFindings removes duplicate findings by title+URL.
func DeduplicateFindings(findings []ParsedFinding) []ParsedFinding {
seen := map[string]bool{}
var out []ParsedFinding
for _, f := range findings {
key := f.Tool + ":" + f.Type + ":" + f.URL + ":" + f.Title
if !seen[key] {
seen[key] = true
out = append(out, f)
}
}
return out
}

// SortFindingsBySeverity sorts findings critical→high→medium→low→info.
func SortFindingsBySeverity(findings []ParsedFinding) []ParsedFinding {
order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
sorted := make([]ParsedFinding, len(findings))
copy(sorted, findings)
for i := 0; i < len(sorted)-1; i++ {
for j := i + 1; j < len(sorted); j++ {
if order[sorted[i].Severity] > order[sorted[j].Severity] {
sorted[i], sorted[j] = sorted[j], sorted[i]
}
}
}
return sorted
}

// FormatFindingsSummary returns a compact summary of all findings.
func FormatFindingsSummary(findings []ParsedFinding) string {
if len(findings) == 0 {
return "  No findings.\n"
}
counts := map[string]int{}
for _, f := range findings {
counts[f.Severity]++
}
var sb strings.Builder
sb.WriteString(fmt.Sprintf("  Findings: %d total", len(findings)))
for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
if n := counts[sev]; n > 0 {
sb.WriteString(fmt.Sprintf(" | %s:%d", strings.ToUpper(sev), n))
}
}
sb.WriteString("\n")
for i, f := range findings {
if i >= 20 {
sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(findings)-20))
break
}
cve := ""
if f.CVE != "" {
cve = " [" + f.CVE + "]"
}
sb.WriteString(fmt.Sprintf("  [%s] %s%s — %s\n",
strings.ToUpper(f.Severity), f.Title, cve, f.URL))
}
return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func normalizeSeverityStr(s string) string {
s = strings.ToLower(strings.TrimSpace(s))
switch s {
case "critical", "high", "medium", "low", "info", "informational":
if s == "informational" {
return "info"
}
return s
default:
return "info"
}
}

func extractCVE(s string) string {
re := regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
if m := re.FindString(s); m != "" {
return m
}
return ""
}

func truncate(s string, max int) string {
if len(s) <= max {
return s
}
return s[:max] + "...[truncated]"
}
