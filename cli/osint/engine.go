// Package osint — CyberMind Deep OSINT Mode
// Linux-only. Full automated OSINT pipeline.
//
// Usage:
//   cybermind /osint-deep <target>              — auto-detect target type, full pipeline
//   cybermind /osint-deep <target> --tools x,y  — specific tools only
//
// Auto-detect:
//   contains @        → email mode
//   starts with +     → phone mode
//   has spaces        → person/company mode
//   is IP (x.x.x.x)  → ip mode
//   else              → domain mode
//
// Phases:
//   Phase 1 — Domain/Subdomain Enumeration (subfinder, amass, dnsx, theHarvester, Sublist3r)
//   Phase 2 — Email OSINT + Breach Hunting (holehe, h8mail, emailfinder, HIBP API, LeakCheck)
//   Phase 3 — Username / People / DOX (sherlock, maigret, WhatsMyName, Epieos, socialscan)
//   Phase 4 — Social Media Scraping (osintgram, twscrape, instaloader, facebook-scraper, Photon)
//   Phase 5 — Company / Org Intelligence (recon-ng, spiderfoot, crosslinked, linkedin2username, ghunt)
//   Phase 6 — Phone / Telecom OSINT (phoneinfoga, OSRFramework)
//   Phase 7 — Image / Video Forensics (exiftool, stegosuite, FOCA)
//   Phase 8 — Dark Web / Paste / Breach (pwndb, trufflehog, gitdorker, OnionSearch, TorBot)
//   Phase 9 — Network Intelligence (nmap OSINT scripts, shodan CLI, sn0int, maltego)
package osint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// OSINTResult holds all findings from the OSINT pipeline.
type OSINTResult struct {
	Target     string
	TargetType string
	Results    []OSINTToolResult
	Tools      []string
	Failed     []OSINTToolResult
	Skipped    []OSINTSkipped
	Context    *OSINTContext
}

// OSINTToolResult holds output from a single OSINT tool.
type OSINTToolResult struct {
	Tool    string
	Output  string
	Error   string
	Partial bool
	Took    time.Duration
}

// OSINTSkipped records a tool that was not run and why.
type OSINTSkipped struct {
	Tool        string
	Reason      string
	InstallHint string
}

// OSINTStatusKind represents the live status of an OSINT tool.
type OSINTStatusKind string

const (
	OSINTRunning     OSINTStatusKind = "running"
	OSINTDone        OSINTStatusKind = "done"
	OSINTFailed      OSINTStatusKind = "failed"
	OSINTKindSkipped OSINTStatusKind = "skipped"
	OSINTPartial     OSINTStatusKind = "partial"
	OSINTRetry       OSINTStatusKind = "retry"
)

// OSINTStatus is emitted for each tool during execution.
type OSINTStatus struct {
	Tool   string
	Kind   OSINTStatusKind
	Reason string
	Took   time.Duration
}

// OSINTContext carries intelligence through the OSINT pipeline.
type OSINTContext struct {
	Target     string
	TargetType string // "domain" | "email" | "username" | "phone" | "ip" | "company"

	// Populated during phases
	EmailsFound     []string
	SubdomainsFound []string
	EmployeesFound  []string
	SocialProfiles  []string
	PhoneInfo       []string
	IPRanges        []string
	GitHubLeaks     []string
	PasteURLs       []string
	GeoLocations    []string
	MetadataFound   []string

	// Session
	SessionDir  string
	StartedAt   time.Time
	LastUpdated time.Time
}

// OSINTSession is persisted to disk.
type OSINTSession struct {
	Target          string            `json:"target"`
	TargetType      string            `json:"target_type"`
	StartedAt       time.Time         `json:"started_at"`
	LastUpdated     time.Time         `json:"last_updated"`
	ToolsRun        []string          `json:"tools_run"`
	Findings        map[string]string `json:"findings"`
	EmailsFound     []string          `json:"emails_found"`
	SubdomainsFound []string          `json:"subdomains_found"`
	EmployeesFound  []string          `json:"employees_found"`
	SocialProfiles  []string          `json:"social_profiles"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var ansiReOSINT = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitizeOSINT(s string, maxLen int) string {
	clean := ansiReOSINT.ReplaceAllString(s, "")
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

// DetectTargetType auto-detects the type of OSINT target from input.
func DetectTargetType(target string) string {
	if strings.Contains(target, "@") {
		return "email"
	}
	if strings.HasPrefix(target, "+") {
		return "phone"
	}
	if net.ParseIP(target) != nil {
		return "ip"
	}
	if strings.Contains(target, " ") {
		return "person"
	}
	// Check if it looks like a domain
	if strings.Contains(target, ".") && !strings.Contains(target, " ") {
		return "domain"
	}
	// Default: username
	return "username"
}

// run executes a command with timeout, returns stdout+stderr.
func run(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Stdin = nil

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

// runShell executes a bash -c command with timeout.
func runShell(timeoutSec int, shellCmd string) (string, error) {
	return run(timeoutSec, "bash", "-c", shellCmd)
}

func dedupOSINT(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func containsStrOSINT(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// writeTempListOSINT writes items to a temp file, returns path or "".
func writeTempListOSINT(items []string) string {
	if len(items) == 0 {
		return ""
	}
	f, err := os.CreateTemp("", "cybermind-osint-*.txt")
	if err != nil {
		return ""
	}
	f.Chmod(0600)
	defer f.Close()
	for _, item := range items {
		f.WriteString(item + "\n")
	}
	return f.Name()
}

// ─── Context Extraction ───────────────────────────────────────────────────────

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var subdomainRe = regexp.MustCompile(`(?i)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`)

func extractEmails(output string) []string {
	matches := emailRe.FindAllString(output, -1)
	return dedupOSINT(matches)
}

func extractSubdomains(output, domain string) []string {
	var subs []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasSuffix(line, "."+domain) || line == domain {
			subs = append(subs, line)
		}
	}
	return dedupOSINT(subs)
}

func extractSocialProfiles(output string) []string {
	var profiles []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "[+]") || strings.Contains(line, "Found") ||
			strings.Contains(line, "http") {
			if strings.TrimSpace(line) != "" {
				profiles = append(profiles, strings.TrimSpace(line))
			}
		}
	}
	return dedupOSINT(profiles)
}

// updateContext enriches OSINTContext from tool output.
func updateContext(tool, output string, ctx *OSINTContext) {
	switch tool {
	case "theHarvester", "emailfinder", "infoga":
		ctx.EmailsFound = dedupOSINT(append(ctx.EmailsFound, extractEmails(output)...))
		ctx.SubdomainsFound = dedupOSINT(append(ctx.SubdomainsFound, extractSubdomains(output, ctx.Target)...))
	case "subfinder", "amass", "dnsx", "sublist3r":
		ctx.SubdomainsFound = dedupOSINT(append(ctx.SubdomainsFound, extractSubdomains(output, ctx.Target)...))
	case "sherlock", "maigret", "socialscan", "holehe":
		ctx.SocialProfiles = dedupOSINT(append(ctx.SocialProfiles, extractSocialProfiles(output)...))
	case "h8mail", "pwndb":
		// breach APIs removed — skip
	case "phoneinfoga":
		ctx.PhoneInfo = append(ctx.PhoneInfo, strings.TrimSpace(output[:min(500, len(output))]))
	case "exiftool", "foca":
		ctx.MetadataFound = append(ctx.MetadataFound, strings.TrimSpace(output[:min(500, len(output))]))
	case "trufflehog", "gitdorker":
		ctx.GitHubLeaks = append(ctx.GitHubLeaks, strings.TrimSpace(output[:min(500, len(output))]))
	case "crosslinked", "linkedin2username":
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				ctx.EmployeesFound = append(ctx.EmployeesFound, line)
			}
		}
		ctx.EmployeesFound = dedupOSINT(ctx.EmployeesFound)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Tool Detection ───────────────────────────────────────────────────────────

var lookPathOSINT = exec.LookPath

func detectOSINTTools(requested []string) (available []OSINTToolSpec, skipped []OSINTSkipped, err error) {
	if requested != nil {
		validSet := make(map[string]bool)
		for _, s := range osintRegistry {
			validSet[s.Name] = true
		}
		for _, name := range requested {
			if !validSet[name] {
				return nil, nil, fmt.Errorf("unknown OSINT tool %q — valid: %s",
					name, strings.Join(OSINTToolNames(), ", "))
			}
		}
	}

	for _, spec := range osintRegistry {
		if requested != nil && !containsStrOSINT(requested, spec.Name) {
			skipped = append(skipped, OSINTSkipped{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		// Check binary exists
		if _, err := lookPathOSINT(spec.Name); err != nil {
			// Check alt paths
			found := false
			for _, alt := range spec.AltPaths {
				if _, e := os.Stat(alt); e == nil {
					found = true
					break
				}
			}
			if !found {
				skipped = append(skipped, OSINTSkipped{
					Tool:        spec.Name,
					Reason:      "not installed",
					InstallHint: spec.InstallHint,
				})
				continue
			}
		}
		available = append(available, spec)
	}
	return available, skipped, nil
}

// ─── Exhaustive Runner ────────────────────────────────────────────────────────

func runOSINTToolExhaustive(spec OSINTToolSpec, target string, ctx *OSINTContext, progress func(OSINTStatus)) (string, error) {
	var output string
	var err error

	if spec.UseShell {
		shellCmd := spec.ShellCmd(target, ctx)
		if shellCmd == "" {
			return "", fmt.Errorf("no shell command")
		}
		output, err = runShell(spec.Timeout, shellCmd)
	} else {
		args := spec.BuildArgs(target, ctx)
		if len(args) == 0 {
			return "", fmt.Errorf("no args — tool not applicable for this target type")
		}
		output, err = run(spec.Timeout, spec.Name, args...)
	}

	if strings.TrimSpace(output) != "" {
		return output, err
	}

	// Try fallbacks
	for i, fallbackFn := range spec.FallbackArgs {
		progress(OSINTStatus{
			Tool:   spec.Name,
			Kind:   OSINTRetry,
			Reason: fmt.Sprintf("primary empty, trying fallback %d/%d", i+1, len(spec.FallbackArgs)),
		})
		fbArgs := fallbackFn(target, ctx)
		if len(fbArgs) == 0 {
			continue
		}
		fbOut, fbErr := run(spec.Timeout, spec.Name, fbArgs...)
		if strings.TrimSpace(fbOut) != "" {
			return fmt.Sprintf("[fallback-%d]\n%s", i+1, fbOut), fbErr
		}
	}

	return output, err
}

// addOSINTResult processes one tool's output into OSINTResult.
func addOSINTResult(result *OSINTResult, spec OSINTToolSpec, output string, err error, took time.Duration) {
	tr := OSINTToolResult{
		Tool: spec.Name,
		Took: took,
	}
	if output != "" {
		tr.Output = sanitizeOSINT(output, 100000)
		tr.Partial = err != nil
		if tr.Partial {
			tr.Error = err.Error()
		}
		result.Tools = append(result.Tools, spec.Name)
	} else if err != nil {
		tr.Error = err.Error()
		result.Failed = append(result.Failed, tr)
	}
	result.Results = append(result.Results, tr)
}

// ─── Session Persistence ──────────────────────────────────────────────────────

func saveOSINTSession(ctx *OSINTContext, findings map[string]string) {
	if ctx.SessionDir == "" {
		return
	}
	toolsRun := make([]string, 0, len(findings))
	for t := range findings {
		toolsRun = append(toolsRun, t)
	}
	session := OSINTSession{
		Target:          ctx.Target,
		TargetType:      ctx.TargetType,
		StartedAt:       ctx.StartedAt,
		LastUpdated:     time.Now(),
		ToolsRun:        toolsRun,
		Findings:        findings,
		EmailsFound:     ctx.EmailsFound,
		SubdomainsFound: ctx.SubdomainsFound,
		EmployeesFound:  ctx.EmployeesFound,
		SocialProfiles:  ctx.SocialProfiles,
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(ctx.SessionDir+"/session.json", data, 0600)
}

func loadOSINTSession(sessionDir string) *OSINTSession {
	data, err := os.ReadFile(sessionDir + "/session.json")
	if err != nil {
		return nil
	}
	var session OSINTSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil
	}
	return &session
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunOSINTDeep executes the full OSINT pipeline against target.
// requested is the --tools filter (nil = run all available).
// progress receives live status events.
func RunOSINTDeep(target string, requested []string, progress func(OSINTStatus)) OSINTResult {
	result := OSINTResult{Target: target}

	// Auto-detect target type
	targetType := DetectTargetType(target)
	result.TargetType = targetType

	ctx := &OSINTContext{
		Target:     target,
		TargetType: targetType,
		StartedAt:  time.Now(),
	}

	// Setup session directory
	safe := strings.NewReplacer("@", "_at_", ".", "_", "+", "", " ", "_", "/", "_").Replace(target)
	ctx.SessionDir = fmt.Sprintf("/tmp/cybermind_osint_%s", safe)
	os.MkdirAll(ctx.SessionDir, 0700)

	// Load previous session
	prev := loadOSINTSession(ctx.SessionDir)
	if prev != nil {
		ctx.EmailsFound = prev.EmailsFound
		ctx.SubdomainsFound = prev.SubdomainsFound
		ctx.EmployeesFound = prev.EmployeesFound
		ctx.SocialProfiles = prev.SocialProfiles
	}

	available, skipped, err := detectOSINTTools(requested)
	if err != nil {
		result.Skipped = append(result.Skipped, OSINTSkipped{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	for _, s := range skipped {
		progress(OSINTStatus{Tool: s.Tool, Kind: OSINTKindSkipped, Reason: s.Reason})
	}

	findings := make(map[string]string)

	runPhase := func(phase int) {
		for _, spec := range available {
			if spec.Phase != phase {
				continue
			}
			// Filter by target type
			if len(spec.TargetTypes) > 0 {
				match := false
				for _, tt := range spec.TargetTypes {
					if tt == "all" || tt == ctx.TargetType {
						match = true
						break
					}
				}
				if !match {
					result.Skipped = append(result.Skipped, OSINTSkipped{
						Tool:   spec.Name,
						Reason: fmt.Sprintf("not applicable for %s targets", ctx.TargetType),
					})
					progress(OSINTStatus{Tool: spec.Name, Kind: OSINTKindSkipped,
						Reason: fmt.Sprintf("not applicable for %s", ctx.TargetType)})
					continue
				}
			}

			progress(OSINTStatus{Tool: spec.Name, Kind: OSINTRunning})
			start := time.Now()
			output, runErr := runOSINTToolExhaustive(spec, target, ctx, progress)
			took := time.Since(start)

			addOSINTResult(&result, spec, output, runErr, took)

			last := result.Results[len(result.Results)-1]
			var kind OSINTStatusKind
			switch {
			case last.Partial:
				kind = OSINTPartial
			case last.Error != "" && last.Output == "":
				kind = OSINTFailed
			default:
				kind = OSINTDone
			}
			progress(OSINTStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})

			if output != "" {
				findings[spec.Name] = output
				updateContext(spec.Name, output, ctx)
				saveOSINTSession(ctx, findings)
			}
		}
	}

	// Run all 9 phases
	for phase := 1; phase <= 9; phase++ {
		runPhase(phase)
	}

	result.Context = ctx
	return result
}

// OSINTToolNames returns all tool names in the OSINT registry.
func OSINTToolNames() []string {
	names := make([]string, len(osintRegistry))
	for i, s := range osintRegistry {
		names[i] = s.Name
	}
	return names
}

// GetOSINTCombinedOutput returns all tool outputs as one string.
func GetOSINTCombinedOutput(r OSINTResult) string {
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
		}
	}
	return b.String()
}
