package recon

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"cybermind-cli/brain"
)

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// isWSL returns true if running inside Windows Subsystem for Linux.
// Raw socket tools (masscan, zmap) don't work on WSL due to kernel limitations.
func isWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

// rawSocketTools are tools that require raw socket access — they fail on WSL.
var rawSocketTools = map[string]bool{
	"masscan": true,
	"zmap":    true,
}

var wordlistCandidates = []string{
	"/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
	os.Getenv("HOME") + "/.local/share/wordlists/common.txt",
}

func resolveWordlist() (string, bool) {
	for _, path := range wordlistCandidates {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

// ToolResult holds output from a single tool
type ToolResult struct {
	Tool    string
	Command string
	Output  string
	Error   string
	Partial bool
	Took    time.Duration
}

// SkippedTool records a tool that was not run and why
type SkippedTool struct {
	Tool        string
	Reason      string
	InstallHint string
}

// ReconResult holds all tool outputs
type ReconResult struct {
	Target  string
	Results []ToolResult
	Tools   []string
	Failed  []ToolResult
	Skipped []SkippedTool
	Context *ReconContext
}

// StatusKind represents the execution status of a tool
type StatusKind string

const (
	StatusRunning StatusKind = "running"
	StatusDone    StatusKind = "done"
	StatusFailed  StatusKind = "failed"
	StatusSkipped StatusKind = "skipped"
	StatusTimeout StatusKind = "timeout"
	StatusPartial StatusKind = "partial"
	StatusRetry   StatusKind = "retry"
)

// ToolStatus reports the live status of a running tool
type ToolStatus struct {
	Tool   string
	Kind   StatusKind
	Reason string
	Took   time.Duration
}

// ReconContext accumulates structured findings across phases
type ReconContext struct {
	Target          string
	TargetType      string
	Subdomains      []string
	LiveHosts       []string
	OpenPorts       []int
	Services        map[int]string
	WAFDetected     bool
	WAFVendor       string
	LiveURLs        []string
	Technologies    []string
	DiscoveredPaths []string
	CrawledURLs     []string
}

// ToolSpec defines a tool's metadata and how to build its arguments
type ToolSpec struct {
	Name         string
	Phase        int
	Timeout      int
	DomainOnly   bool
	CascadeGroup string
	// CascadeBackup: if true, this tool only runs if the cascade primary produced no output
	CascadeBackup bool
	BuildArgs    func(target string, ctx *ReconContext) []string
	// FallbackArgs: if primary run returns empty output, try these args instead.
	// This ensures 100% tool usage — we exhaust every option before giving up.
	FallbackArgs []func(target string, ctx *ReconContext) []string
	NeedsFile    string
	InstallHint  string
}

// lookPath is the function used to check if a binary exists.
var lookPath = exec.LookPath

// isAvailable checks if a tool is installed
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// detectTools filters toolRegistry based on availability, --tools flag, wordlist, and cascade groups.
func detectTools(requested []string) (available []ToolSpec, skipped []SkippedTool, err error) {
	if requested != nil {
		registryNames := make(map[string]bool)
		for _, spec := range toolRegistry {
			registryNames[spec.Name] = true
		}
		for _, name := range requested {
			if !registryNames[name] {
				return nil, nil, fmt.Errorf("unknown tool: %q — run 'cybermind /tools' to see valid tool names", name)
			}
		}
	}

	// cascadeWinners: first installed tool per group (primary)
	// cascadeBackups: remaining installed tools per group (run only if primary fails)
	cascadeWinners := map[string]string{}
	cascadeBackups := map[string][]ToolSpec{}

	for _, spec := range toolRegistry {
		if requested != nil && !containsStr(requested, spec.Name) {
			skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		// Skip raw socket tools on WSL — they require kernel raw socket support
		if rawSocketTools[spec.Name] && isWSL() {
			skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "skipped on WSL (raw sockets not supported)"})
			continue
		}
		if _, err := lookPath(spec.Name); err != nil {
			skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "not installed", InstallHint: spec.InstallHint})
			continue
		}
		if spec.NeedsFile == "wordlist" {
			if _, found := resolveWordlist(); !found {
				skipped = append(skipped, SkippedTool{
					Tool:   spec.Name,
					Reason: "no wordlist found — install seclists: sudo apt install seclists",
				})
				continue
			}
		}
		if spec.CascadeGroup != "" {
			if _, taken := cascadeWinners[spec.CascadeGroup]; taken {
				// Mark as backup — will run if primary produces no output
				backup := spec
				backup.CascadeBackup = true
				cascadeBackups[spec.CascadeGroup] = append(cascadeBackups[spec.CascadeGroup], backup)
				continue
			}
			cascadeWinners[spec.CascadeGroup] = spec.Name
		}
		available = append(available, spec)
	}

	// Append cascade backups after their primary (skipped unless primary fails)
	for _, backups := range cascadeBackups {
		available = append(available, backups...)
	}

	return available, skipped, nil
}

func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// run executes a command with timeout, returns output
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

// runToolExhaustive runs a tool with its primary args, then tries each FallbackArgs
// if the primary run returns empty output. This ensures 100% tool usage —
// we exhaust every command variant before moving to the next tool.
//
// Logic:
//   1. Run primary BuildArgs → if output found, done.
//   2. If empty → try FallbackArgs[0] → if output found, done.
//   3. If still empty → try FallbackArgs[1] → ... and so on.
//   4. Only after ALL variants exhausted with no output → mark as failed.
func runToolExhaustive(spec ToolSpec, target string, ctx *ReconContext, progress func(ToolStatus)) (string, error) {
	// Primary run
	args := spec.BuildArgs(target, ctx)
	output, err := run(spec.Timeout, spec.Name, args...)

	// If we got output, return immediately — tool succeeded
	if strings.TrimSpace(output) != "" {
		return output, err
	}

	// Primary returned empty — try each fallback variant
	for i, fallbackFn := range spec.FallbackArgs {
		progress(ToolStatus{
			Tool:   spec.Name,
			Kind:   StatusRetry,
			Reason: fmt.Sprintf("primary returned empty, trying fallback %d/%d", i+1, len(spec.FallbackArgs)),
		})

		fbArgs := fallbackFn(target, ctx)
		fbOutput, fbErr := run(spec.Timeout, spec.Name, fbArgs...)

		if strings.TrimSpace(fbOutput) != "" {
			// Fallback produced output — prepend note and return
			return fmt.Sprintf("[fallback-%d used]\n%s", i+1, fbOutput), fbErr
		}
		// This fallback also empty — try next
		_ = fbErr
	}

	// All variants exhausted — return whatever we have (likely empty + error)
	return output, err
}

// sanitize removes ANSI codes and trims output to max length
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitize(s string, maxLen int) string {
	clean := ansiRe.ReplaceAllString(s, "")
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

// validateTarget checks that target contains only safe characters.
var targetRe = regexp.MustCompile(`^[a-zA-Z0-9._:\-/\[\]]+$`)

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	check := target
	if strings.HasPrefix(strings.ToLower(check), "www.") {
		check = check[4:]
	}
	if !targetRe.MatchString(target) {
		return fmt.Errorf("invalid target %q — use hostname, IP, or CIDR (e.g. example.com, 192.168.1.1, 10.0.0.0/24)", target)
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("invalid target %q — target cannot start with '-'", target)
	}
	if strings.Contains(target, "--") {
		return fmt.Errorf("invalid target %q — target cannot contain '--'", target)
	}
	_ = check
	return nil
}

// ValidateTarget is exported for use by main.go
func ValidateTarget(target string) error {
	return validateTarget(target)
}

func targetType(target string) string {
	if net.ParseIP(target) != nil {
		return "ip"
	}
	return "domain"
}

func isIP(target string) bool {
	return targetType(target) == "ip"
}

// addResult processes a tool's execution result and updates ReconResult.
func addResult(result *ReconResult, spec ToolSpec, output string, err error, took time.Duration) {
	tr := ToolResult{
		Tool:    spec.Name,
		Command: spec.Name,
		Took:    took,
	}
	if output != "" {
		tr.Output = sanitize(output, 50000)
		tr.Partial = err != nil
		if tr.Partial {
			tr.Error = err.Error()
			tr.Output += "\n[partial — exited non-zero: " + err.Error() + "]"
		}
		result.Tools = append(result.Tools, spec.Name)
	} else if err != nil {
		tr.Error = err.Error()
		result.Failed = append(result.Failed, tr)
	}
	result.Results = append(result.Results, tr)
}

// autoInstallMissingTools checks which tools from the provided list are missing
// and installs them silently using apt/go install/pip3.
// Returns the list of tools that were successfully installed.
func autoInstallMissingTools(tools []string) []string {
	var installed []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			continue // already installed
		}
		// Find the tool spec to get install hint
		var hint string
		for _, spec := range toolRegistry {
			if spec.Name == tool {
				hint = spec.InstallHint
				break
			}
		}
		if hint == "" {
			continue
		}
		// Try apt install
		if strings.HasPrefix(hint, "sudo apt install") {
			pkg := strings.TrimPrefix(hint, "sudo apt install ")
			pkg = strings.Fields(pkg)[0]
			cmd := exec.Command("sudo", "apt-get", "install", "-y", "-qq", pkg)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			cmd.Stdin = nil
			if cmd.Run() == nil {
				if _, e := exec.LookPath(tool); e == nil {
					installed = append(installed, tool)
					continue
				}
			}
		}
		// Try go install
		if strings.HasPrefix(hint, "go install") {
			parts := strings.Fields(hint)
			if len(parts) >= 3 {
				cmd := exec.Command("go", "install", parts[2])
				cmd.Stdin = nil
				if cmd.Run() == nil {
					// Symlink from ~/go/bin
					home, _ := os.UserHomeDir()
					for _, gobin := range []string{home + "/go/bin/" + tool, "/root/go/bin/" + tool} {
						if _, e := os.Stat(gobin); e == nil {
							exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+tool).Run()
							break
						}
					}
					if _, e := exec.LookPath(tool); e == nil {
						installed = append(installed, tool)
						continue
					}
				}
			}
		}
		// Try pip3 install
		if strings.HasPrefix(hint, "pip3 install") {
			parts := strings.Fields(hint)
			if len(parts) >= 3 {
				pkg := parts[2]
				cmd := exec.Command("pip3", "install", pkg, "--break-system-packages", "-q")
				cmd.Stdin = nil
				if cmd.Run() == nil {
					if _, e := exec.LookPath(tool); e == nil {
						installed = append(installed, tool)
					}
				}
			}
		}
	}
	return installed
}

// RunAutoRecon runs all available recon tools against target in phase order.
// Each tool is run exhaustively — primary args first, then fallbacks if empty.
func RunAutoRecon(target string, requested []string, progress func(ToolStatus)) ReconResult {
	result := ReconResult{Target: target}

	if err := validateTarget(target); err != nil {
		result.Skipped = append(result.Skipped, SkippedTool{Tool: "all", Reason: err.Error()})
		return result
	}

	ctx := &ReconContext{
		Target:     target,
		TargetType: targetType(target),
	}

	// Auto-install missing tools silently before running
	allToolNames := ToolNames()
	autoInstallMissingTools(allToolNames)

	available, skipped, err := detectTools(requested)
	if err != nil {
		result.Skipped = append(result.Skipped, SkippedTool{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	for _, s := range skipped {
		progress(ToolStatus{Tool: s.Tool, Kind: StatusSkipped, Reason: s.Reason})
	}

	// runPhase executes all tools for a phase — each tool runs exhaustively
	runPhase := func(phase int) {
		// Track which cascade groups produced output (primary succeeded)
		cascadeGroupSuccess := map[string]bool{}

		for _, spec := range available {
			if spec.Phase != phase {
				continue
			}
			// Skip cascade backup if primary already produced output
			if spec.CascadeBackup {
				if cascadeGroupSuccess[spec.CascadeGroup] {
					result.Skipped = append(result.Skipped, SkippedTool{Tool: spec.Name, Reason: "cascade: primary succeeded"})
					progress(ToolStatus{Tool: spec.Name, Kind: StatusSkipped, Reason: "cascade: primary succeeded"})
					continue
				}
			}
			if spec.DomainOnly && ctx.TargetType == "ip" {
				result.Skipped = append(result.Skipped, SkippedTool{Tool: spec.Name, Reason: "domain-only tool"})
				progress(ToolStatus{Tool: spec.Name, Kind: StatusSkipped, Reason: "domain-only tool"})
				continue
			}

			progress(ToolStatus{Tool: spec.Name, Kind: StatusRunning})
			start := time.Now()

			// ── EXHAUSTIVE RUN: primary → fallbacks → give up ──────────────
			output, runErr := runToolExhaustive(spec, target, ctx, progress)
			took := time.Since(start)

			addResult(&result, spec, output, runErr, took)

			last := result.Results[len(result.Results)-1]
			var kind StatusKind
			switch {
			case last.Partial:
				kind = StatusPartial
			case last.Error != "" && last.Output == "":
				kind = StatusFailed
			default:
				kind = StatusDone
			}
			progress(ToolStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})

			// ── Brain self-learning: record every tool run ─────────────────
			// This feeds the adaptive intelligence system — confidence scores
			// update in real-time so future scans prioritize effective tools.
			toolSuccess := last.Output != "" && last.Error == ""
			brain.RecordToolRun(target, spec.Name, took, toolSuccess, 0, nil, last.Error)

			// Mark cascade group as succeeded if this tool produced output
			if spec.CascadeGroup != "" && last.Output != "" {
				cascadeGroupSuccess[spec.CascadeGroup] = true
			}
		}
	}

	// Phase 1 — Passive OSINT
	runPhase(1)

	// Phase 2 — Subdomain Enum → populate ctx.Subdomains and ctx.LiveHosts
	runPhase(2)
	ctx.Subdomains = extractSubdomains(result)
	ctx.LiveHosts = extractLiveHosts(result)

	// Phase 3 — Port Scan → populate ctx.OpenPorts, ctx.WAFDetected
	runPhase(3)
	ctx.OpenPorts = extractOpenPorts(result)
	ctx.WAFDetected, ctx.WAFVendor = extractWAF(result)

	// Adaptive: auto-queue tlsx if 443 or 8443 found
	if containsPort(ctx.OpenPorts, 443) || containsPort(ctx.OpenPorts, 8443) {
		available = ensureToolQueued("tlsx", available, toolRegistry)
	}

	// Adaptive: skip phases 4/5/6 if no open ports found AND target is an IP
	// For domain targets: always continue — port scan may have failed but HTTP probing
	// can still find live services (especially as root where raw socket output differs)
	if len(ctx.OpenPorts) == 0 && ctx.TargetType == "ip" {
		buildCombined(&result)
		result.Context = ctx
		return result
	}
	// For domain targets with no ports: inject common web ports so httpx still runs
	if len(ctx.OpenPorts) == 0 && ctx.TargetType == "domain" {
		ctx.OpenPorts = []int{80, 443, 8080, 8443}
	}

	// Phase 4 — HTTP Probe → populate ctx.LiveURLs
	runPhase(4)
	ctx.LiveURLs = extractLiveURLs(result)

	// Phase 5 — Dir Discovery
	runPhase(5)

	// Phase 6 — Vuln Scan: katana first (crawl) → nuclei uses crawled URLs → nikto
	runKatanaFirst := func() {
		for _, spec := range available {
			if spec.Phase == 6 && spec.Name == "katana" {
				if spec.DomainOnly && ctx.TargetType == "ip" {
					continue
				}
				progress(ToolStatus{Tool: spec.Name, Kind: StatusRunning})
				start := time.Now()
				output, runErr := runToolExhaustive(spec, target, ctx, progress)
				took := time.Since(start)
				addResult(&result, spec, output, runErr, took)
				last := result.Results[len(result.Results)-1]
				var kind StatusKind
				switch {
				case last.Partial:
					kind = StatusPartial
				case last.Error != "" && last.Output == "":
					kind = StatusFailed
				default:
					kind = StatusDone
				}
				progress(ToolStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})
				ctx.CrawledURLs = extractCrawledURLs(result)
				return
			}
		}
	}
	runKatanaFirst()

	// Run remaining phase 6 tools (nuclei, nikto) — skip katana (already ran)
	for _, spec := range available {
		if spec.Phase != 6 || spec.Name == "katana" {
			continue
		}
		if spec.DomainOnly && ctx.TargetType == "ip" {
			result.Skipped = append(result.Skipped, SkippedTool{Tool: spec.Name, Reason: "domain-only tool"})
			progress(ToolStatus{Tool: spec.Name, Kind: StatusSkipped, Reason: "domain-only tool"})
			continue
		}
		progress(ToolStatus{Tool: spec.Name, Kind: StatusRunning})
		start := time.Now()
		output, runErr := runToolExhaustive(spec, target, ctx, progress)
		took := time.Since(start)
		addResult(&result, spec, output, runErr, took)
		last := result.Results[len(result.Results)-1]
		var kind StatusKind
		switch {
		case last.Partial:
			kind = StatusPartial
		case last.Error != "" && last.Output == "":
			kind = StatusFailed
		default:
			kind = StatusDone
		}
		progress(ToolStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})
	}

	buildCombined(&result)
	result.Context = ctx

	// ── Brain: record completed scan session ──────────────────────────────
	// Updates the self-model with what we found — future scans learn from this.
	go func() {
		var bugTypes []string
		var techStack []string
		if ctx != nil {
			techStack = ctx.Technologies
		}
		brain.RecordScanComplete(brain.ScanObservation{
			Target:      target,
			Mode:        "recon",
			StartTime:   time.Now().Add(-30 * time.Minute), // approximate
			EndTime:     time.Now(),
			BugsFound:   0, // recon doesn't find bugs directly
			BugTypes:    bugTypes,
			TechStack:   techStack,
			WAFDetected: ctx != nil && ctx.WAFDetected,
			WAFVendor:   func() string { if ctx != nil { return ctx.WAFVendor }; return "" }(),
			Decision:    "recon complete — proceed to hunt",
			Outcome:     func() string { if len(result.Tools) > 0 { return "success" }; return "partial" }(),
		})
	}()

	return result
}

// GetCombinedOutput returns all tool outputs as one string
func GetCombinedOutput(r ReconResult) string {
	for _, tr := range r.Results {
		if tr.Tool == "combined" {
			return tr.Output
		}
	}
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString("=== " + strings.ToUpper(tr.Tool) + " ===\n")
			b.WriteString(tr.Output + "\n\n")
		}
	}
	return b.String()
}

// CheckTools returns which recon tools are available
func CheckTools() map[string]bool {
	tools := []string{
		"nmap", "masscan", "rustscan", "naabu",
		"subfinder", "amass", "httpx", "whatweb",
		"dig", "whois", "nuclei", "dnsx",
		"gobuster", "ffuf", "feroxbuster",
		"nikto", "katana", "tlsx",
		"reconftw",
	}
	result := make(map[string]bool)
	for _, t := range tools {
		result[t] = isAvailable(t)
	}
	return result
}
