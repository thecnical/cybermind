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
		// Merge previous findings into context
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

	// Phase 0: Pre-install all missing tools
	for _, spec := range tools {
		if !isAvailable(spec.Name) {
			InstallTool(spec, progress)
		}
	}

	// Run tools phase by phase
	var results []ExploitResult
	findings := make(map[string]string)

	for phase := 1; phase <= 6; phase++ {
		for _, spec := range tools {
			if spec.Phase != phase {
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
				// Save progress after each tool
				saveSession(ctx, findings)
			}
		}
	}

	// Final session save
	saveSession(ctx, findings)
	return results
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
