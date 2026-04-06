package hunt

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// HuntResult holds all findings from the hunt pipeline.
type HuntResult struct {
	Target   string
	Results  []HuntToolResult
	Tools    []string       // tools that produced output
	Failed   []HuntToolResult
	Skipped  []HuntSkipped
	Context  *HuntContext
}

// HuntToolResult holds output from a single hunt tool.
type HuntToolResult struct {
	Tool    string
	Command string
	Output  string
	Error   string
	Partial bool
	Took    time.Duration
}

// HuntSkipped records a tool that was not run and why.
type HuntSkipped struct {
	Tool        string
	Reason      string
	InstallHint string
}

// HuntStatusKind represents the live status of a hunt tool.
type HuntStatusKind string

const (
	HuntRunning HuntStatusKind = "running"
	HuntDone    HuntStatusKind = "done"
	HuntFailed  HuntStatusKind = "failed"
	HuntKindSkipped HuntStatusKind = "skipped"
	HuntPartial HuntStatusKind = "partial"
)

// HuntStatus is emitted for each tool during execution.
type HuntStatus struct {
	Tool   string
	Kind   HuntStatusKind
	Reason string
	Took   time.Duration
}

// HuntContext carries recon intelligence into the hunt pipeline.
// Populated either from a prior /recon run or from manual flags.
type HuntContext struct {
	Target      string
	TargetType  string   // "domain" | "ip"
	LiveURLs    []string // from recon httpx output
	CrawledURLs []string // from recon katana output
	OpenPorts   []int
	WAFDetected bool
	WAFVendor   string
	Subdomains  []string

	// Hunt findings
	XSSFound        []string
	ParamsFound     []string
	HistoricalURLs  []string
	VulnsFound      []string
}

// HuntToolSpec defines a hunt tool.
type HuntToolSpec struct {
	Name        string
	Phase       int
	Timeout     int
	DomainOnly  bool
	BuildArgs   func(target string, ctx *HuntContext) []string
	InstallHint string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitize(s string, maxLen int) string {
	clean := ansiRe.ReplaceAllString(s, "")
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

func targetType(target string) string {
	if net.ParseIP(target) != nil {
		return "ip"
	}
	return "domain"
}

// lookPath can be overridden in tests.
var lookPath = exec.LookPath

func isAvailable(tool string) bool {
	_, err := lookPath(tool)
	return err == nil
}

// run executes a command with timeout, returns stdout+stderr.
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

// writeTempList writes items to a temp file, returns path or "".
func writeTempList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	f, err := os.CreateTemp("", "cybermind-hunt-*.txt")
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, item := range items {
		f.WriteString(item + "\n")
	}
	return f.Name()
}

// addResult processes one tool's output into HuntResult.
func addResult(result *HuntResult, spec HuntToolSpec, output string, err error, took time.Duration) {
	tr := HuntToolResult{
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

// detectHuntTools filters huntRegistry based on availability and --tools flag.
func detectHuntTools(requested []string) (available []HuntToolSpec, skipped []HuntSkipped, err error) {
	if requested != nil {
		validSet := make(map[string]bool)
		for _, s := range huntRegistry {
			validSet[s.Name] = true
		}
		for _, name := range requested {
			if !validSet[name] {
				return nil, nil, fmt.Errorf("unknown hunt tool %q — valid: %s",
					name, strings.Join(HuntToolNames(), ", "))
			}
		}
	}

	for _, spec := range huntRegistry {
		if requested != nil && !containsStr(requested, spec.Name) {
			skipped = append(skipped, HuntSkipped{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		if _, err := lookPath(spec.Name); err != nil {
			skipped = append(skipped, HuntSkipped{
				Tool:        spec.Name,
				Reason:      "not installed",
				InstallHint: spec.InstallHint,
			})
			continue
		}
		available = append(available, spec)
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

// ─── Context Extraction ───────────────────────────────────────────────────────

// extractXSS parses dalfox output for confirmed XSS findings.
func extractXSS(result HuntResult) []string {
	var found []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "dalfox" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(strings.ToLower(line), "poc") ||
				strings.Contains(strings.ToLower(line), "verified") ||
				strings.Contains(strings.ToLower(line), "[v]") {
				if !seen[line] {
					seen[line] = true
					found = append(found, line)
				}
			}
		}
	}
	return found
}

// extractHistoricalURLs parses gau/waybackurls output.
var urlRe = regexp.MustCompile(`https?://[^\s]+`)

func extractHistoricalURLs(result HuntResult) []string {
	var urls []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "gau" && tr.Tool != "waybackurls" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if m := urlRe.FindString(line); m != "" && !seen[m] {
				seen[m] = true
				urls = append(urls, m)
			}
		}
	}
	return urls
}

// extractParams parses x8 output for discovered parameters.
func extractParams(result HuntResult) []string {
	var params []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "x8" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				seen[line] = true
				params = append(params, line)
			}
		}
	}
	return params
}

// extractVulns parses nuclei hunt output for confirmed vulnerabilities.
func extractVulns(result HuntResult) []string {
	var vulns []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "nuclei-hunt" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !seen[line] {
				seen[line] = true
				vulns = append(vulns, line)
			}
		}
	}
	return vulns
}

// buildHuntCombined assembles combined output.
func buildHuntCombined(result *HuntResult) string {
	var b strings.Builder
	for _, tr := range result.Results {
		if tr.Output == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
	}
	return b.String()
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunHunt executes the full hunt pipeline against target.
// ctx carries intelligence from a prior /recon run (can be nil for manual mode).
// requested is the --tools filter (nil = run all available).
// progress receives live status events.
func RunHunt(target string, ctx *HuntContext, requested []string, progress func(HuntStatus)) HuntResult {
	result := HuntResult{Target: target}

	if ctx == nil {
		ctx = &HuntContext{
			Target:     target,
			TargetType: targetType(target),
		}
	}

	available, skipped, err := detectHuntTools(requested)
	if err != nil {
		result.Skipped = append(result.Skipped, HuntSkipped{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	// Emit skipped statuses upfront
	for _, s := range skipped {
		progress(HuntStatus{Tool: s.Tool, Kind: HuntKindSkipped, Reason: s.Reason})
	}

	runTool := func(spec HuntToolSpec) {
		// Skip domain-only tools for IP targets
		if spec.DomainOnly && ctx.TargetType == "ip" {
			result.Skipped = append(result.Skipped, HuntSkipped{Tool: spec.Name, Reason: "domain-only tool"})
			progress(HuntStatus{Tool: spec.Name, Kind: HuntKindSkipped, Reason: "domain-only tool"})
			return
		}

		progress(HuntStatus{Tool: spec.Name, Kind: HuntRunning})
		start := time.Now()
		args := spec.BuildArgs(target, ctx)
		output, runErr := run(spec.Timeout, spec.Name, args...)
		took := time.Since(start)

		addResult(&result, spec, output, runErr, took)

		last := result.Results[len(result.Results)-1]
		var kind HuntStatusKind
		switch {
		case last.Partial:
			kind = HuntPartial
		case last.Error != "" && last.Output == "":
			kind = HuntFailed
		default:
			kind = HuntDone
		}
		progress(HuntStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})
	}

	// ── Phase 1: URL Collection ──────────────────────────────────────────────
	// gau + waybackurls — collect all historical URLs
	for _, spec := range available {
		if spec.Phase == 1 {
			runTool(spec)
		}
	}
	ctx.HistoricalURLs = extractHistoricalURLs(result)

	// ── Phase 2: Deep Crawl ──────────────────────────────────────────────────
	// katana — deep JS crawl on live URLs from recon
	for _, spec := range available {
		if spec.Phase == 2 {
			runTool(spec)
		}
	}
	// Merge crawled URLs into context
	for _, tr := range result.Results {
		if tr.Tool == "katana-hunt" {
			for _, line := range strings.Split(tr.Output, "\n") {
				line = strings.TrimSpace(line)
				if m := urlRe.FindString(line); m != "" {
					ctx.CrawledURLs = append(ctx.CrawledURLs, m)
				}
			}
		}
	}

	// ── Phase 3: Parameter Discovery ────────────────────────────────────────
	// x8 — hidden parameter discovery on live URLs
	for _, spec := range available {
		if spec.Phase == 3 {
			runTool(spec)
		}
	}
	ctx.ParamsFound = extractParams(result)

	// ── Phase 4: XSS Hunting ────────────────────────────────────────────────
	// dalfox — XSS on all collected URLs
	for _, spec := range available {
		if spec.Phase == 4 {
			runTool(spec)
		}
	}
	ctx.XSSFound = extractXSS(result)

	// ── Phase 5: Deep Vulnerability Scan ────────────────────────────────────
	// nuclei with full template set on all discovered URLs
	for _, spec := range available {
		if spec.Phase == 5 {
			runTool(spec)
		}
	}
	ctx.VulnsFound = extractVulns(result)

	// ── Phase 6: Network Vuln Scripts ───────────────────────────────────────
	// nmap --script vuln on open ports
	for _, spec := range available {
		if spec.Phase == 6 {
			runTool(spec)
		}
	}

	result.Context = ctx
	return result
}

// HuntToolNames returns all tool names in the hunt registry.
func HuntToolNames() []string {
	names := make([]string, len(huntRegistry))
	for i, s := range huntRegistry {
		names[i] = s.Name
	}
	return names
}

// GetHuntCombinedOutput returns all tool outputs as one string.
func GetHuntCombinedOutput(r HuntResult) string {
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString("=== " + strings.ToUpper(tr.Tool) + " ===\n")
			b.WriteString(tr.Output + "\n\n")
		}
	}
	return b.String()
}
