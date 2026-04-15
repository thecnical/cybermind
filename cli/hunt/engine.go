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
	Target  string
	Results []HuntToolResult
	Tools   []string // tools that produced output
	Failed  []HuntToolResult
	Skipped []HuntSkipped
	Context *HuntContext
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
	HuntRunning     HuntStatusKind = "running"
	HuntDone        HuntStatusKind = "done"
	HuntFailed      HuntStatusKind = "failed"
	HuntKindSkipped HuntStatusKind = "skipped"
	HuntPartial     HuntStatusKind = "partial"
	HuntRetry       HuntStatusKind = "retry"
)

// HuntStatus is emitted for each tool during execution.
type HuntStatus struct {
	Tool   string
	Kind   HuntStatusKind
	Reason string
	Took   time.Duration
}

// HuntContext carries intelligence through the hunt pipeline.
// Populated from a prior /recon run OR built up during hunt phases.
type HuntContext struct {
	Target     string
	TargetType string // "domain" | "ip"

	// From /recon (pre-populated if chained)
	LiveURLs    []string // httpx-confirmed live URLs
	CrawledURLs []string // katana-crawled endpoints
	OpenPorts   []int
	WAFDetected bool
	WAFVendor   string
	Subdomains  []string
	Technologies []string // detected tech stack from recon (whatweb, wappalyzer)

	// Populated during hunt phases
	HistoricalURLs []string // waymore + gau + waybackurls
	AllURLs        []string // merged: LiveURLs + CrawledURLs + HistoricalURLs (deduped)
	ParamsFound    []string // paramspider + arjun + x8 hidden parameters
	XSSFound       []string // xsstrike + dalfox confirmed XSS
	VulnsFound     []string // nuclei confirmed vulns
	GFPatterns     map[string][]string // gf pattern matches: xss, sqli, ssrf, lfi, rce
}

// HuntToolSpec defines a hunt tool.
type HuntToolSpec struct {
	Name          string
	Phase         int
	Timeout       int
	DomainOnly    bool
	CascadeGroup  string // only first available in group runs
	CascadeBackup bool   // if true, only runs if cascade primary produced no output
	BuildArgs     func(target string, ctx *HuntContext) []string
	// FallbackArgs: tried in order if primary returns empty output.
	// Ensures 100% tool usage — exhaust every variant before giving up.
	FallbackArgs []func(target string, ctx *HuntContext) []string
	InstallHint  string
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

// validateTarget checks that target contains only safe characters.
// Prevents tool flag injection via crafted target strings.
var targetRe = regexp.MustCompile(`^[a-zA-Z0-9._:\-/\[\]]+$`)

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	if !targetRe.MatchString(target) {
		return fmt.Errorf("invalid target %q — use hostname, IP, or CIDR (e.g. example.com, 192.168.1.1)", target)
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("invalid target %q — target cannot start with '-'", target)
	}
	if strings.Contains(target, "--") {
		return fmt.Errorf("invalid target %q — target cannot contain '--'", target)
	}
	return nil
}

func targetType(target string) string {
	if net.ParseIP(target) != nil {
		return "ip"
	}
	return "domain"
}

// lookPath can be overridden in tests.
var lookPath = exec.LookPath

// run executes a command with timeout, returns stdout+stderr.
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

// writeTempList writes items to a temp file, returns path or "".
// Uses 0600 permissions — temp files may contain sensitive target data.
func writeTempList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	f, err := os.CreateTemp("", "cybermind-hunt-*.txt")
	if err != nil {
		return ""
	}
	// Secure permissions before writing
	f.Chmod(0600)
	defer f.Close()
	for _, item := range items {
		f.WriteString(item + "\n")
	}
	return f.Name()
}

// dedup returns a deduplicated copy of a string slice.
func dedup(items []string) []string {
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

// runHuntToolExhaustive runs a hunt tool with primary args, then fallbacks if empty.
// Ensures 100% tool usage — exhaust every command variant before giving up.
func runHuntToolExhaustive(spec HuntToolSpec, target string, ctx *HuntContext, progress func(HuntStatus)) (string, error) {
	args := spec.BuildArgs(target, ctx)
	output, err := run(spec.Timeout, spec.Name, args...)

	if strings.TrimSpace(output) != "" {
		return output, err
	}

	for i, fallbackFn := range spec.FallbackArgs {
		progress(HuntStatus{
			Tool:   spec.Name,
			Kind:   HuntRetry,
			Reason: fmt.Sprintf("primary returned empty, trying fallback %d/%d", i+1, len(spec.FallbackArgs)),
		})
		fbArgs := fallbackFn(target, ctx)
		fbOutput, fbErr := run(spec.Timeout, spec.Name, fbArgs...)
		if strings.TrimSpace(fbOutput) != "" {
			return fmt.Sprintf("[fallback-%d used]\n%s", i+1, fbOutput), fbErr
		}
		_ = fbErr
	}

	return output, err
}

// addResult processes one tool's output into HuntResult.
func addResult(result *HuntResult, spec HuntToolSpec, output string, err error, took time.Duration) {
	tr := HuntToolResult{
		Tool:    spec.Name,
		Command: spec.Name,
		Took:    took,
	}
	if output != "" {
		tr.Output = sanitize(output, 50000) // increased — full tool output for AI analysis
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

// detectHuntTools filters huntRegistry based on availability, --tools flag, and cascade groups.
func detectHuntTools(requested []string) (available []HuntToolSpec, skipped []HuntSkipped, err error) {
	// Validate requested tool names
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

	cascadeWinners := map[string]string{}
	cascadeBackups := map[string][]HuntToolSpec{}

	for _, spec := range huntRegistry {
		// Filter by --tools flag
		if requested != nil && !containsStr(requested, spec.Name) {
			skipped = append(skipped, HuntSkipped{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		// Check binary exists
		if _, err := lookPath(spec.Name); err != nil {
			skipped = append(skipped, HuntSkipped{
				Tool:        spec.Name,
				Reason:      "not installed",
				InstallHint: spec.InstallHint,
			})
			continue
		}
		// Cascade: only first available in group runs; backups run if primary fails
		if spec.CascadeGroup != "" {
			if _, taken := cascadeWinners[spec.CascadeGroup]; taken {
				backup := spec
				backup.CascadeBackup = true
				cascadeBackups[spec.CascadeGroup] = append(cascadeBackups[spec.CascadeGroup], backup)
				continue
			}
			cascadeWinners[spec.CascadeGroup] = spec.Name
		}
		available = append(available, spec)
	}

	// Append cascade backups after their primary
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

// ─── Context Extraction ───────────────────────────────────────────────────────

var urlRe = regexp.MustCompile(`https?://[^\s\[\]"'<>]+`)

// extractHistoricalURLs parses gau/waybackurls output for URLs.
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

// extractCrawledURLs parses katana output for discovered endpoints.
func extractCrawledURLs(result HuntResult) []string {
	var urls []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "katana" {
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

// extractXSS parses dalfox output for confirmed XSS findings.
// Only accepts lines with explicit [v] or [vuln] markers — not generic "found".
func extractXSS(result HuntResult) []string {
	var found []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "dalfox" && tr.Tool != "kxss" && tr.Tool != "bxss" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			// Must have explicit confirmation — not just "found" which is too loose
			confirmed := strings.Contains(lower, "[v]") ||
				strings.Contains(lower, "[vuln]") ||
				strings.Contains(lower, "poc") ||
				strings.Contains(lower, "verified")
			if !confirmed {
				continue
			}
			// Skip negative lines
			if strings.Contains(lower, "not") && strings.Contains(lower, "vuln") {
				continue
			}
			if !seen[line] && line != "" {
				seen[line] = true
				found = append(found, line)
			}
		}
	}
	return found
}

// extractVulns parses nuclei output for confirmed vulnerabilities.
// Only accepts lines matching nuclei's [severity][template][url] format.
var nucleiLineRe = regexp.MustCompile(`\[(critical|high|medium|low|info)\]\s+\[`)

func extractVulns(result HuntResult) []string {
	var vulns []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "nuclei" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Must match nuclei's output format — not just any line
			if !nucleiLineRe.MatchString(line) {
				continue
			}
			// Skip info-only lines unless they contain interesting keywords
			lower := strings.ToLower(line)
			if strings.Contains(line, "[info]") {
				if !strings.Contains(lower, "exposed") && !strings.Contains(lower, "secret") &&
					!strings.Contains(lower, "token") && !strings.Contains(lower, "key") &&
					!strings.Contains(lower, "takeover") {
					continue
				}
			}
			if !seen[line] {
				seen[line] = true
				vulns = append(vulns, line)
			}
		}
	}
	return vulns
}

// mergeAllURLs combines LiveURLs + CrawledURLs + HistoricalURLs into one deduped list.
// Prioritizes confirmed live URLs first, then crawled, then historical.
func mergeAllURLs(ctx *HuntContext) []string {
	var all []string
	all = append(all, ctx.LiveURLs...)
	all = append(all, ctx.CrawledURLs...)
	all = append(all, ctx.HistoricalURLs...)
	return dedup(all)
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunHunt executes the full hunt pipeline against target.
// ctx carries intelligence from a prior /recon run (nil = manual mode, starts fresh).
// requested is the --tools filter (nil = run all available).
// progress receives live status events.
func RunHunt(target string, ctx *HuntContext, requested []string, progress func(HuntStatus)) HuntResult {
	result := HuntResult{Target: target}

	// Security: validate target before passing to any external tool
	if err := validateTarget(target); err != nil {
		result.Skipped = append(result.Skipped, HuntSkipped{Tool: "all", Reason: err.Error()})
		return result
	}

	// Initialize context if not provided (manual mode)
	if ctx == nil {
		ctx = &HuntContext{
			Target:     target,
			TargetType: targetType(target),
		}
	}
	// Ensure TargetType is set
	if ctx.TargetType == "" {
		ctx.TargetType = targetType(target)
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

	// runPhase executes all available tools for a given phase number.
	// Mirrors recon's runPhase for consistency.
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
					result.Skipped = append(result.Skipped, HuntSkipped{
						Tool:   spec.Name,
						Reason: "cascade: primary succeeded",
					})
					progress(HuntStatus{Tool: spec.Name, Kind: HuntKindSkipped, Reason: "cascade: primary succeeded"})
					continue
				}
			}
			// Skip domain-only tools for IP targets
			if spec.DomainOnly && ctx.TargetType == "ip" {
				result.Skipped = append(result.Skipped, HuntSkipped{
					Tool:   spec.Name,
					Reason: "domain-only tool",
				})
				progress(HuntStatus{Tool: spec.Name, Kind: HuntKindSkipped, Reason: "domain-only tool"})
				continue
			}

			progress(HuntStatus{Tool: spec.Name, Kind: HuntRunning})
			start := time.Now()
			// Exhaustive run: primary → fallbacks → give up
			output, runErr := runHuntToolExhaustive(spec, target, ctx, progress)
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

			// Mark cascade group as succeeded if this tool produced output
			if spec.CascadeGroup != "" && last.Output != "" {
				cascadeGroupSuccess[spec.CascadeGroup] = true
			}
		}
	}

	// ── Phase 1: URL Collection ──────────────────────────────────────────────
	// gau + waybackurls → historical URLs from archives
	runPhase(1)
	ctx.HistoricalURLs = extractHistoricalURLs(result)

	// ── Phase 2: Deep Crawl ──────────────────────────────────────────────────
	// katana → deep JS crawl, discovers endpoints, forms, API paths
	// Uses LiveURLs from recon if available, else root target
	runPhase(2)
	newCrawled := extractCrawledURLs(result)
	ctx.CrawledURLs = dedup(append(ctx.CrawledURLs, newCrawled...))

	// ── Adaptive: merge all URLs into AllURLs for downstream phases ──────────
	ctx.AllURLs = mergeAllURLs(ctx)

	// Adaptive: if no URLs found at all, skip web-based phases
	if len(ctx.AllURLs) == 0 && len(ctx.LiveURLs) == 0 {
		// Still run network vuln scan (phase 6) since it works on IP/domain directly
		runPhase(6)
		result.Context = ctx
		return result
	}

	// ── Phase 3: Parameter Discovery ────────────────────────────────────────
	// x8 → hidden GET/POST parameters on live URLs
	// Only run if we have live URLs to test
	if len(ctx.LiveURLs) > 0 || len(ctx.AllURLs) > 0 {
		runPhase(3)
		ctx.ParamsFound = extractParams(result)
	} else {
		// Skip x8 — no URLs to test parameters on
		for _, spec := range available {
			if spec.Phase == 3 {
				result.Skipped = append(result.Skipped, HuntSkipped{
					Tool:   spec.Name,
					Reason: "no live URLs to test — run /recon first or provide a live target",
				})
				progress(HuntStatus{Tool: spec.Name, Kind: HuntKindSkipped,
					Reason: "no live URLs"})
			}
		}
	}

	// ── Phase 4: XSS Hunting ────────────────────────────────────────────────
	// dalfox → XSS on all collected URLs
	// Adaptive: WAF detected → add delay to avoid blocks
	runPhase(4)
	ctx.XSSFound = extractXSS(result)

	// ── Phase 5: Deep Vulnerability Scan ────────────────────────────────────
	// nuclei → full template set (critical/high/medium/low)
	// Uses CrawledURLs > LiveURLs > target (in priority order)
	runPhase(5)
	ctx.VulnsFound = extractVulns(result)

	// ── Phase 6: Network Vulnerability Scripts ───────────────────────────────
	// nmap --script vuln → network-level CVEs on open ports
	// Adaptive: uses known open ports from recon if available (faster)
	runPhase(6)

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
			b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
		}
	}
	return b.String()
}
