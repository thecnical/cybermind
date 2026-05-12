// brain/agents.go — 16 Specialist Agents for OMEGA Multi-Agent System
// Each agent has a specific role, tools, and real execution logic.
// Agents run in parallel goroutines with a shared result channel.
package brain

import (
"fmt"
"os/exec"
"strings"
"sync"
"time"
)

// AgentRole identifies which specialist agent this is
type AgentRole string

const (
AgentRecon        AgentRole = "recon"
AgentSubdomain    AgentRole = "subdomain"
AgentPortScan     AgentRole = "portscan"
AgentHTTPProbe    AgentRole = "httpprobe"
AgentJSIntel      AgentRole = "jsintel"
AgentSecretScan   AgentRole = "secretscan"
AgentXSS          AgentRole = "xss"
AgentSQLi         AgentRole = "sqli"
AgentSSRF         AgentRole = "ssrf"
AgentNuclei       AgentRole = "nuclei"
AgentOAuth        AgentRole = "oauth"
AgentBizLogic     AgentRole = "bizlogic"
AgentWAFBypass    AgentRole = "wafbypass"
AgentCloudMisconf AgentRole = "cloudmisconf"
AgentSmuggling    AgentRole = "smuggling"
AgentExploit      AgentRole = "exploit"
)

// Agent is a specialist that runs one phase of the attack
type Agent struct {
Role        AgentRole
Name        string
Description string
Tools       []string
Phase       int // 1=recon, 2=hunt, 3=exploit
}

// All16Agents returns the complete list of 16 specialist agents
func All16Agents() []Agent {
return []Agent{
// ── Phase 1: Recon Agents (6) ─────────────────────────────────────
{AgentRecon, "Passive OSINT Agent",
"WHOIS, DNS, theHarvester, email enum, ASN mapping",
[]string{"whois", "dig", "theHarvester", "asnmap"}, 1},
{AgentSubdomain, "Subdomain Enum Agent",
"subfinder, amass, puredns, alterx, dnsx — finds all subdomains",
[]string{"subfinder", "amass", "puredns", "dnsx", "alterx"}, 1},
{AgentPortScan, "Port Scan Agent",
"naabu, nmap, masscan, rustscan — full port coverage",
[]string{"naabu", "nmap", "masscan"}, 1},
{AgentHTTPProbe, "HTTP Fingerprint Agent",
"httpx, whatweb, wafw00f, tlsx, gowitness — tech stack + screenshots",
[]string{"httpx", "whatweb", "wafw00f", "gowitness"}, 1},
{AgentJSIntel, "JS Intelligence Agent",
"jsluice, linkfinder, sourcemapper — extract endpoints/secrets from JS",
[]string{"jsluice", "katana", "gau"}, 1},
{AgentSecretScan, "Secret Scanner Agent",
"trufflehog, gitleaks, nuclei exposures — find leaked keys/tokens",
[]string{"trufflehog", "gitleaks", "nuclei"}, 1},
// ── Phase 2: Hunt Agents (7) ──────────────────────────────────────
{AgentXSS, "XSS Hunter Agent",
"dalfox, kxss, bxss — reflected/stored/DOM XSS with WAF bypass",
[]string{"dalfox", "kxss", "gau", "waybackurls"}, 2},
{AgentSQLi, "SQLi Agent",
"sqlmap, ghauri — SQL injection with tamper scripts",
[]string{"sqlmap", "ghauri"}, 2},
{AgentSSRF, "SSRF Agent",
"ssrfmap, nuclei, interactsh — SSRF + OOB detection",
[]string{"nuclei", "interactsh-client"}, 2},
{AgentNuclei, "Nuclei Template Agent",
"nuclei critical+high+medium — 9000+ templates, CVE detection",
[]string{"nuclei"}, 2},
{AgentOAuth, "OAuth/JWT Agent",
"jwt_tool, nuclei — OAuth misconfig, JWT attacks, PKCE bypass",
[]string{"jwt_tool", "nuclei"}, 2},
{AgentBizLogic, "Business Logic Agent",
"custom HTTP tests — price manipulation, IDOR, race conditions",
[]string{"ffuf", "nuclei"}, 2},
{AgentWAFBypass, "WAF Bypass Agent",
"sqlmap tampers, dalfox bypass — Cloudflare/Akamai/AWS bypass",
[]string{"sqlmap", "dalfox"}, 2},
// ── Phase 3: Exploit Agents (3) ───────────────────────────────────
{AgentCloudMisconf, "Cloud Misconfig Agent",
"cloud_enum, pacu, nuclei — S3/GCS/Azure bucket exposure",
[]string{"cloud_enum", "nuclei", "pacu"}, 3},
{AgentSmuggling, "HTTP Smuggling Agent",
"smuggler, nuclei — CL.TE, TE.CL, H2 desync detection",
[]string{"nuclei"}, 3},
{AgentExploit, "Exploit Verification Agent",
"metasploit, searchsploit, nuclei — verify and PoC confirmed bugs",
[]string{"searchsploit", "nuclei", "msfconsole"}, 3},
}
}

// AgentDispatcher runs multiple agents in parallel and streams results
type AgentDispatcher struct {
Target   string
Agents   []Agent
Results  chan AgentResult
Memory   *TargetMemory
mu       sync.Mutex
wg       sync.WaitGroup
}

// NewAgentDispatcher creates a dispatcher for the given target
func NewAgentDispatcher(target string, agents []Agent) *AgentDispatcher {
return &AgentDispatcher{
Target:  target,
Agents:  agents,
Results: make(chan AgentResult, len(agents)*2),
Memory:  LoadTarget(target),
}
}

// RunPhase runs all agents for a given phase in parallel
// onProgress is called for each line of output (for TUI display)
func (d *AgentDispatcher) RunPhase(phase int, onProgress func(AgentRole, string)) {
var phaseAgents []Agent
for _, a := range d.Agents {
if a.Phase == phase {
phaseAgents = append(phaseAgents, a)
}
}

for _, agent := range phaseAgents {
d.wg.Add(1)
go func(a Agent) {
defer d.wg.Done()
start := time.Now()
output, findings := runAgent(a, d.Target, d.Memory, func(line string) {
if onProgress != nil {
onProgress(a.Role, line)
}
})
d.Results <- AgentResult{
AgentID:  a.Role,
Name:     a.Name,
Status:   AgentDone,
Output:   output,
Findings: findings,
Duration: time.Since(start),
}
}(agent)
}
d.wg.Wait()
}

// Wait waits for all agents to finish
func (d *AgentDispatcher) Wait() {
d.wg.Wait()
close(d.Results)
}

// runAgent executes a single agent and returns output + findings
func runAgent(a Agent, target string, mem *TargetMemory, onLine func(string)) (string, []Bug) {
var sb strings.Builder
var findings []Bug

baseURL := target
if !strings.HasPrefix(baseURL, "http") {
baseURL = "https://" + target
}

runTool := func(name string, args ...string) string {
if _, err := exec.LookPath(name); err != nil {
return ""
}
cmd := exec.Command(name, args...)
out, err := cmd.Output()
if err != nil && len(out) == 0 {
return ""
}
result := strings.TrimSpace(string(out))
if onLine != nil && result != "" {
for _, line := range strings.Split(result, "\n")[:min16(5, strings.Count(result, "\n")+1)] {
if strings.TrimSpace(line) != "" {
onLine(fmt.Sprintf("[%s] %s", a.Role, line))
}
}
}
return result
}

switch a.Role {

case AgentRecon:
onLine(fmt.Sprintf("[%s] Starting passive OSINT...", a.Role))
if out := runTool("whois", target); out != "" {
sb.WriteString("=WHOIS=\n" + out[:min16(500, len(out))] + "\n")
}
if out := runTool("dig", target, "ANY", "+short"); out != "" {
sb.WriteString("=DNS=\n" + out + "\n")
}
if out := runTool("asnmap", "-d", target, "-silent"); out != "" {
sb.WriteString("=ASN=\n" + out + "\n")
}

case AgentSubdomain:
onLine(fmt.Sprintf("[%s] Enumerating subdomains...", a.Role))
if out := runTool("subfinder", "-d", target, "-silent", "-t", "100"); out != "" {
sb.WriteString("=SUBFINDER=\n" + out + "\n")
count := strings.Count(out, "\n") + 1
onLine(fmt.Sprintf("[%s] Found %d subdomains via subfinder", a.Role, count))
}
if out := runTool("dnsx", "-d", target, "-silent", "-a", "-resp"); out != "" {
sb.WriteString("=DNSX=\n" + out + "\n")
}
if out := runTool("alterx", "-d", target, "-silent"); out != "" {
sb.WriteString("=ALTERX=\n" + out[:min16(2000, len(out))] + "\n")
}

case AgentPortScan:
onLine(fmt.Sprintf("[%s] Scanning ports...", a.Role))
if out := runTool("naabu", "-host", target, "-silent", "-top-ports", "1000"); out != "" {
sb.WriteString("=NAABU=\n" + out + "\n")
onLine(fmt.Sprintf("[%s] Port scan complete", a.Role))
} else if out := runTool("nmap", "-sV", "--top-ports", "100", "-T4", target); out != "" {
sb.WriteString("=NMAP=\n" + out[:min16(3000, len(out))] + "\n")
}

case AgentHTTPProbe:
onLine(fmt.Sprintf("[%s] Fingerprinting HTTP services...", a.Role))
if out := runTool("httpx", "-u", baseURL, "-title", "-tech-detect", "-status-code", "-silent"); out != "" {
sb.WriteString("=HTTPX=\n" + out + "\n")
}
if out := runTool("whatweb", "-a", "3", "--no-errors", baseURL); out != "" {
sb.WriteString("=WHATWEB=\n" + out[:min16(1000, len(out))] + "\n")
}
if out := runTool("wafw00f", baseURL, "-a"); out != "" {
sb.WriteString("=WAF=\n" + out[:min16(500, len(out))] + "\n")
if strings.Contains(strings.ToLower(out), "is behind") {
onLine(fmt.Sprintf("[%s] WAF detected!", a.Role))
}
}
if out := runTool("gowitness", "single", "--url", baseURL, "--screenshot-path", "/tmp/cybermind_screenshots"); out != "" {
sb.WriteString("=SCREENSHOT=\n" + out + "\n")
}

case AgentJSIntel:
onLine(fmt.Sprintf("[%s] Extracting JS intelligence...", a.Role))
if out := runTool("katana", "-u", baseURL, "-silent", "-jc", "-d", "3"); out != "" {
sb.WriteString("=KATANA=\n" + out[:min16(5000, len(out))] + "\n")
}
if out := runTool("gau", "--subs", "--threads", "10", target); out != "" {
count := strings.Count(out, "\n") + 1
sb.WriteString(fmt.Sprintf("=GAU= %d URLs\n", count))
onLine(fmt.Sprintf("[%s] Collected %d historical URLs", a.Role, count))
}
if out := runTool("jsluice", "urls", "-r", baseURL); out != "" {
sb.WriteString("=JSLUICE=\n" + out[:min16(3000, len(out))] + "\n")
}

case AgentSecretScan:
onLine(fmt.Sprintf("[%s] Scanning for exposed secrets...", a.Role))
if out := runTool("trufflehog", "http", "--url", baseURL, "--json", "--no-update"); out != "" {
if strings.Contains(out, "DetectorName") {
sb.WriteString("=TRUFFLEHOG=\n" + out[:min16(2000, len(out))] + "\n")
findings = append(findings, Bug{
Title: "Exposed Secrets/API Keys", Type: "secret_exposure",
URL: baseURL, Severity: "critical",
Evidence: out[:min16(300, len(out))], Tool: "trufflehog",
})
onLine(fmt.Sprintf("[%s] CRITICAL: Secrets found!", a.Role))
}
}
if out := runTool("nuclei", "-u", baseURL, "-t", "exposures,tokens", "-silent", "-no-color"); out != "" {
sb.WriteString("=NUCLEI-SECRETS=\n" + out + "\n")
}

case AgentXSS:
onLine(fmt.Sprintf("[%s] Hunting XSS vulnerabilities...", a.Role))
if out := runTool("dalfox", "url", baseURL, "--silence", "--no-color", "--waf-bypass"); out != "" {
sb.WriteString("=DALFOX=\n" + out + "\n")
lower := strings.ToLower(out)
if strings.Contains(lower, "[v]") || strings.Contains(lower, "poc") {
findings = append(findings, Bug{
Title: "Cross-Site Scripting (XSS)", Type: "xss",
URL: baseURL, Severity: "high",
Evidence: out[:min16(300, len(out))], Tool: "dalfox", Verified: true,
})
onLine(fmt.Sprintf("[%s] HIGH: XSS found!", a.Role))
}
}
if out := runTool("kxss", "-u", baseURL); out != "" {
sb.WriteString("=KXSS=\n" + out + "\n")
}

case AgentSQLi:
onLine(fmt.Sprintf("[%s] Testing SQL injection...", a.Role))
if out := runTool("sqlmap", "-u", baseURL+"/?id=1",
"--level=3", "--risk=2", "--batch", "--random-agent",
"--output-dir=/tmp/cybermind_sqlmap", "--forms"); out != "" {
sb.WriteString("=SQLMAP=\n" + out[:min16(3000, len(out))] + "\n")
lower := strings.ToLower(out)
if strings.Contains(lower, "is vulnerable") || strings.Contains(lower, "parameter") {
findings = append(findings, Bug{
Title: "SQL Injection", Type: "sqli",
URL: baseURL, Severity: "critical",
Evidence: out[:min16(300, len(out))], Tool: "sqlmap", Verified: true,
})
onLine(fmt.Sprintf("[%s] CRITICAL: SQLi found!", a.Role))
}
}

case AgentSSRF:
onLine(fmt.Sprintf("[%s] Testing SSRF vectors...", a.Role))
if out := runTool("nuclei", "-u", baseURL,
"-t", "ssrf,oast", "-silent", "-no-color"); out != "" {
sb.WriteString("=NUCLEI-SSRF=\n" + out + "\n")
if strings.Contains(strings.ToLower(out), "[critical]") || strings.Contains(strings.ToLower(out), "[high]") {
findings = append(findings, Bug{
Title: "Server-Side Request Forgery (SSRF)", Type: "ssrf",
URL: baseURL, Severity: "high",
Evidence: out[:min16(300, len(out))], Tool: "nuclei",
})
}
}

case AgentNuclei:
onLine(fmt.Sprintf("[%s] Running 9000+ nuclei templates...", a.Role))
if out := runTool("nuclei", "-u", baseURL,
"-severity", "critical,high,medium",
"-silent", "-no-color", "-c", "50", "-timeout", "10",
"-rate-limit", "150"); out != "" {
sb.WriteString("=NUCLEI=\n" + out + "\n")
for _, line := range strings.Split(out, "\n") {
line = strings.TrimSpace(line)
if line == "" {
continue
}
lower := strings.ToLower(line)
sev := "medium"
if strings.Contains(lower, "[critical]") {
sev = "critical"
} else if strings.Contains(lower, "[high]") {
sev = "high"
}
if strings.Contains(lower, "[critical]") || strings.Contains(lower, "[high]") {
findings = append(findings, Bug{
Title: "Nuclei: " + line[:min16(80, len(line))],
Type: "nuclei", URL: baseURL, Severity: sev,
Evidence: line, Tool: "nuclei",
})
onLine(fmt.Sprintf("[%s] %s: %s", a.Role, strings.ToUpper(sev), line[:min16(60, len(line))]))
}
}
}

case AgentOAuth:
onLine(fmt.Sprintf("[%s] Testing OAuth/JWT...", a.Role))
if out := runTool("nuclei", "-u", baseURL,
"-t", "token-spray,oauth,jwt", "-silent", "-no-color"); out != "" {
sb.WriteString("=NUCLEI-OAUTH=\n" + out + "\n")
}

case AgentBizLogic:
onLine(fmt.Sprintf("[%s] Testing business logic...", a.Role))
if out := runTool("ffuf", "-u", baseURL+"/FUZZ",
"-w", "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
"-mc", "200,201,204", "-silent"); out != "" {
sb.WriteString("=FFUF-API=\n" + out[:min16(3000, len(out))] + "\n")
}

case AgentWAFBypass:
onLine(fmt.Sprintf("[%s] Attempting WAF bypass...", a.Role))
if mem.WAFDetected {
onLine(fmt.Sprintf("[%s] WAF: %s — selecting bypass tampers", a.Role, mem.WAFVendor))
tampers := selectWAFTampers(mem.WAFVendor)
if out := runTool("sqlmap", "-u", baseURL+"/?id=1",
"--tamper="+tampers, "--batch", "--level=2", "--risk=1",
"--output-dir=/tmp/cybermind_waf"); out != "" {
sb.WriteString("=WAF-BYPASS-SQLMAP=\n" + out[:min16(2000, len(out))] + "\n")
}
} else {
onLine(fmt.Sprintf("[%s] No WAF detected — skipping bypass", a.Role))
}

case AgentCloudMisconf:
onLine(fmt.Sprintf("[%s] Checking cloud misconfigurations...", a.Role))
if out := runTool("nuclei", "-u", baseURL,
"-t", "cloud,s3,azure,gcp", "-silent", "-no-color"); out != "" {
sb.WriteString("=NUCLEI-CLOUD=\n" + out + "\n")
}

case AgentSmuggling:
onLine(fmt.Sprintf("[%s] Testing HTTP request smuggling...", a.Role))
if out := runTool("nuclei", "-u", baseURL,
"-t", "http-smuggling", "-silent", "-no-color"); out != "" {
sb.WriteString("=SMUGGLING=\n" + out + "\n")
if strings.Contains(strings.ToLower(out), "[high]") || strings.Contains(strings.ToLower(out), "[critical]") {
findings = append(findings, Bug{
Title: "HTTP Request Smuggling", Type: "smuggling",
URL: baseURL, Severity: "high",
Evidence: out[:min16(300, len(out))], Tool: "nuclei",
})
}
}

case AgentExploit:
onLine(fmt.Sprintf("[%s] Verifying and exploiting confirmed bugs...", a.Role))
if len(mem.BugsFound) > 0 {
for _, bug := range mem.BugsFound {
if !bug.Verified {
onLine(fmt.Sprintf("[%s] Verifying: %s", a.Role, bug.Title))
if out := runTool("nuclei", "-u", bug.URL, "-silent", "-no-color"); out != "" {
sb.WriteString(fmt.Sprintf("=VERIFY-%s=\n%s\n", bug.Type, out[:min16(500, len(out))]))
}
}
}
}
if out := runTool("searchsploit", "--json", target); out != "" {
sb.WriteString("=SEARCHSPLOIT=\n" + out[:min16(2000, len(out))] + "\n")
}
}

return sb.String(), findings
}

// selectWAFTampers returns the best sqlmap tamper scripts for a WAF vendor
func selectWAFTampers(wafVendor string) string {
lower := strings.ToLower(wafVendor)
switch {
case strings.Contains(lower, "cloudflare"):
return "space2comment,randomcase,between,charunicodeencode"
case strings.Contains(lower, "akamai"):
return "space2comment,randomcase,urlencode,htmlencode"
case strings.Contains(lower, "aws") || strings.Contains(lower, "waf"):
return "space2comment,randomcase,between"
case strings.Contains(lower, "imperva") || strings.Contains(lower, "incapsula"):
return "space2comment,randomcase,charunicodeencode,urlencode"
case strings.Contains(lower, "f5") || strings.Contains(lower, "bigip"):
return "space2comment,randomcase,between,urlencode"
default:
return "space2comment,randomcase,urlencode"
}
}

func min16(a, b int) int {
if a < b {
return a
}
return b
}

