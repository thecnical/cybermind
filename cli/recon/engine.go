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
)

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
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
	BuildArgs    func(target string, ctx *ReconContext) []string
	NeedsFile    string
	InstallHint  string
}



// lookPath is the function used to check if a binary exists.
// It can be overridden in tests.
var lookPath = exec.LookPath

// isAvailable checks if a tool is installed
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// detectTools filters toolRegistry based on availability, --tools flag, wordlist, and cascade groups.
// Returns available tools and a list of skipped tools with reasons.
func detectTools(requested []string) (available []ToolSpec, skipped []SkippedTool, err error) {
	// Validate requested tool names against registry
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

	cascadeWinners := map[string]string{} // group → winning tool name

	for _, spec := range toolRegistry {
		// Filter by --tools flag
		if requested != nil && !containsStr(requested, spec.Name) {
			skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		// Check binary exists
		if _, err := lookPath(spec.Name); err != nil {
			skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "not installed", InstallHint: spec.InstallHint})
			continue
		}
		// Check NeedsFile dependency
		if spec.NeedsFile == "wordlist" {
			if _, found := resolveWordlist(); !found {
				skipped = append(skipped, SkippedTool{
					Tool:   spec.Name,
					Reason: "no wordlist found — install seclists: sudo apt install seclists",
				})
				continue
			}
		}
		// Cascade: only first available in group wins
		if spec.CascadeGroup != "" {
			if winner, taken := cascadeWinners[spec.CascadeGroup]; taken {
				skipped = append(skipped, SkippedTool{Tool: spec.Name, Reason: "cascade: " + winner + " used"})
				continue
			}
			cascadeWinners[spec.CascadeGroup] = spec.Name
		}
		available = append(available, spec)
	}
	return available, skipped, nil
}

// containsStr checks if a string slice contains a value
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
// Prevents nmap/tool flag injection via crafted target strings.
// Regex: ^[a-zA-Z0-9._:\-/\[\]]+$ — covers:
//   - Hostnames: example.com, sub.example.com
//   - IPv4: 192.168.1.1
//   - IPv6: [::1], 2001:db8::1
//   - CIDR: 192.168.1.0/24
//   - Ports: example.com:8080
// Blocks: spaces, --, ;, |, &, $, `, (, ), {, }, <, >, \, ', "
var targetRe = regexp.MustCompile(`^[a-zA-Z0-9._:\-/\[\]]+$`)

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	// Strip www. prefix for validation (common user input)
	check := target
	if strings.HasPrefix(strings.ToLower(check), "www.") {
		check = check[4:]
	}
	if !targetRe.MatchString(target) {
		return fmt.Errorf("invalid target %q — use hostname, IP, or CIDR (e.g. example.com, 192.168.1.1, 10.0.0.0/24)", target)
	}
	// Reject anything starting with - (flag injection)
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("invalid target %q — target cannot start with '-'", target)
	}
	// Reject double-dash (flag injection like --script-args)
	if strings.Contains(target, "--") {
		return fmt.Errorf("invalid target %q — target cannot contain '--'", target)
	}
	_ = check
	return nil
}

// ValidateTarget checks that target contains only safe characters.
// Exported for use by main.go before calling RunAutoRecon.
func ValidateTarget(target string) error {
	return validateTarget(target)
}
func targetType(target string) string {
	if net.ParseIP(target) != nil {
		return "ip"
	}
	return "domain"
}

// isIP checks if target looks like an IP address
func isIP(target string) bool {
	return targetType(target) == "ip"
}

// addResult processes a tool's execution result and updates ReconResult accordingly.
// Three-branch logic:
//   - output != "" → store sanitized output, set Partial=(err!=nil), append error annotation, add to result.Tools
//   - output == "" && err != nil → add to result.Failed with error
//   - output == "" && err == nil → no-op (tool ran but produced nothing)
func addResult(result *ReconResult, spec ToolSpec, output string, err error, took time.Duration) {
	tr := ToolResult{
		Tool:    spec.Name,
		Command: spec.Name,
		Took:    took,
	}
	if output != "" {
		tr.Output = sanitize(output, 6000)
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

// RunAutoRecon runs all available recon tools against target in phase order.
// requested is the --tools filter (nil = run all). progress receives live status events.
func RunAutoRecon(target string, requested []string, progress func(ToolStatus)) ReconResult {
	result := ReconResult{Target: target}

	// Security: validate target before passing to any external tool
	if err := validateTarget(target); err != nil {
		result.Skipped = append(result.Skipped, SkippedTool{Tool: "all", Reason: err.Error()})
		return result
	}

	ctx := &ReconContext{
		Target:     target,
		TargetType: targetType(target),
	}

	available, skipped, err := detectTools(requested)
	if err != nil {
		// Unknown tool in --tools flag — return error in result
		result.Skipped = append(result.Skipped, SkippedTool{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	// Emit skipped statuses upfront
	for _, s := range skipped {
		progress(ToolStatus{Tool: s.Tool, Kind: StatusSkipped, Reason: s.Reason})
	}

	// runPhase executes all available tools for a given phase number
	runPhase := func(phase int) {
		for _, spec := range available {
			if spec.Phase != phase {
				continue
			}
			// Skip domain-only tools for IP targets
			if spec.DomainOnly && ctx.TargetType == "ip" {
				result.Skipped = append(result.Skipped, SkippedTool{
					Tool:   spec.Name,
					Reason: "domain-only tool",
				})
				progress(ToolStatus{Tool: spec.Name, Kind: StatusSkipped, Reason: "domain-only tool"})
				continue
			}

			progress(ToolStatus{Tool: spec.Name, Kind: StatusRunning})
			start := time.Now()
			args := spec.BuildArgs(target, ctx)
			output, runErr := run(spec.Timeout, spec.Name, args...)
			took := time.Since(start)

			addResult(&result, spec, output, runErr, took)

			// Determine status kind for progress callback
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

	// Adaptive: skip phases 4/5/6 if no open ports found
	if len(ctx.OpenPorts) == 0 {
		buildCombined(&result)
		result.Context = ctx
		return result
	}

	// Phase 4 — HTTP Probe on live hosts → populate ctx.LiveURLs
	runPhase(4)
	ctx.LiveURLs = extractLiveURLs(result)

	// Phase 5 — Dir Discovery on each live URL (WAF-adaptive rate limiting handled in BuildArgs)
	runPhase(5)

	// Phase 6 — Vuln Scan: katana first → populate ctx.CrawledURLs → nuclei uses them
	// Run katana before nuclei by running phase 6 tools in registry order
	// (katana is last in registry, but nuclei needs crawled URLs — run katana first if available)
	// Actually: registry order is nuclei, nikto, katana. We need katana before nuclei.
	// Solution: run katana separately first, then run the rest of phase 6.
	runKatanaFirst := func() {
		for _, spec := range available {
			if spec.Phase == 6 && spec.Name == "katana" {
				if spec.DomainOnly && ctx.TargetType == "ip" {
					continue
				}
				progress(ToolStatus{Tool: spec.Name, Kind: StatusRunning})
				start := time.Now()
				args := spec.BuildArgs(target, ctx)
				output, runErr := run(spec.Timeout, spec.Name, args...)
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
		args := spec.BuildArgs(target, ctx)
		output, runErr := run(spec.Timeout, spec.Name, args...)
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
		"nmap", "masscan", "rustscan",
		"subfinder", "amass", "httpx", "whatweb",
		"dig", "whois", "nuclei",
		"gobuster", "ffuf", "feroxbuster",
		"nikto", "sqlmap", "burpsuite",
	}
	result := make(map[string]bool)
	for _, t := range tools {
		result[t] = isAvailable(t)
	}
	return result
}
