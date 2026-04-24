package devsec

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/storage"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// DevSecResult holds all findings from the DevSec pipeline.
type DevSecResult struct {
	Target      string
	Phase1      []ToolResult  // trufflehog, gitleaks
	Phase2      []ToolResult  // semgrep
	Phase3      []ToolResult  // trivy, npm audit, pip-audit
	Skipped     []SkippedTool
	CombinedRaw string // ANSI-stripped, sent to backend
}

// ToolResult holds output from a single tool.
type ToolResult struct {
	Tool   string
	Output string
	Error  string
	Took   time.Duration
}

// SkippedTool records a tool that was not run and why.
type SkippedTool struct {
	Tool        string
	InstallHint string
}

// ─── ANSI Stripping ───────────────────────────────────────────────────────────

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// stripANSI removes ANSI escape sequences from a string.
func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// ─── Target Classification ────────────────────────────────────────────────────

// githubURLRe matches exactly https://github.com/<owner>/<repo>
// Owner and repo must be non-empty and contain only valid GitHub identifier chars.
var githubURLRe = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$`)

// isGitHubURL returns true if target matches https://github.com/<owner>/<repo>
func isGitHubURL(target string) bool {
	return githubURLRe.MatchString(target)
}

// ─── Repo Cloning ─────────────────────────────────────────────────────────────

// cloneRepo clones a GitHub URL to a temp dir, returns the temp path.
// Caller must defer os.RemoveAll(tempPath).
func cloneRepo(url string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "cybermind-devsec-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	cmd := exec.Command("git", "clone", "--depth=0", url, tmpDir)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = nil

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("git clone failed: %w\n%s", err, out.String())
	}

	return tmpDir, nil
}

// ─── Tool Availability ────────────────────────────────────────────────────────

// isAvailable checks if a tool binary is in PATH.
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// ─── Tool Execution ───────────────────────────────────────────────────────────

// runTool executes a command with a timeout and returns its combined output.
func runTool(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out strings.Builder
	var errOut strings.Builder
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

// ─── Phase Runners ────────────────────────────────────────────────────────────

// runPhase1 runs secret scanning tools (trufflehog, gitleaks) against dir.
func runPhase1(dir string, progress func(string)) ([]ToolResult, []SkippedTool) {
	var results []ToolResult
	var skipped []SkippedTool

	tools := []struct {
		name        string
		args        func(string) []string
		installHint string
		timeout     int
	}{
		{
			name:        "trufflehog",
			args:        func(d string) []string { return []string{"filesystem", d, "--json"} },
			installHint: "brew install trufflesecurity/trufflehog/trufflehog  OR  pip install trufflehog",
			timeout:     120,
		},
		{
			name:        "gitleaks",
			args:        func(d string) []string { return []string{"detect", "--source", d, "--no-git"} },
			installHint: "brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest",
			timeout:     120,
		},
	}

	for _, t := range tools {
		if !isAvailable(t.name) {
			skipped = append(skipped, SkippedTool{Tool: t.name, InstallHint: t.installHint})
			continue
		}
		progress(fmt.Sprintf("[devsec] running %s...", t.name))
		start := time.Now()
		output, err := runTool(t.timeout, t.name, t.args(dir)...)
		tr := ToolResult{
			Tool:   t.name,
			Output: stripANSI(output),
			Took:   time.Since(start),
		}
		if err != nil {
			tr.Error = err.Error()
		}
		results = append(results, tr)
	}

	return results, skipped
}

// runPhase2 runs SAST tools (semgrep) against dir.
func runPhase2(dir string, progress func(string)) ([]ToolResult, []SkippedTool) {
	var results []ToolResult
	var skipped []SkippedTool

	if !isAvailable("semgrep") {
		skipped = append(skipped, SkippedTool{
			Tool:        "semgrep",
			InstallHint: "pip install semgrep  OR  brew install semgrep",
		})
		return results, skipped
	}

	progress("[devsec] running semgrep...")
	start := time.Now()
	output, err := runTool(180, "semgrep", "--config=p/security-audit", dir, "--json")
	tr := ToolResult{
		Tool:   "semgrep",
		Output: stripANSI(output),
		Took:   time.Since(start),
	}
	if err != nil {
		tr.Error = err.Error()
	}
	results = append(results, tr)

	return results, skipped
}

// runPhase3 runs dependency audit tools (trivy, npm audit, pip-audit) against dir.
func runPhase3(dir string, progress func(string)) ([]ToolResult, []SkippedTool) {
	var results []ToolResult
	var skipped []SkippedTool

	// trivy filesystem scan
	if !isAvailable("trivy") {
		skipped = append(skipped, SkippedTool{
			Tool:        "trivy",
			InstallHint: "brew install aquasecurity/trivy/trivy  OR  apt install trivy",
		})
	} else {
		progress("[devsec] running trivy...")
		start := time.Now()
		output, err := runTool(180, "trivy", "fs", dir, "--format", "json")
		tr := ToolResult{
			Tool:   "trivy",
			Output: stripANSI(output),
			Took:   time.Since(start),
		}
		if err != nil {
			tr.Error = err.Error()
		}
		results = append(results, tr)
	}

	// npm audit — only if package.json present
	if _, err := os.Stat(dir + "/package.json"); err == nil {
		if !isAvailable("npm") {
			skipped = append(skipped, SkippedTool{
				Tool:        "npm audit",
				InstallHint: "install Node.js from https://nodejs.org",
			})
		} else {
			progress("[devsec] running npm audit...")
			start := time.Now()
			output, err := runTool(120, "npm", "audit", "--json", "--prefix", dir)
			tr := ToolResult{
				Tool:   "npm audit",
				Output: stripANSI(output),
				Took:   time.Since(start),
			}
			if err != nil {
				tr.Error = err.Error()
			}
			results = append(results, tr)
		}
	}

	// pip-audit — only if requirements.txt or pyproject.toml present
	_, hasReqs := os.Stat(dir + "/requirements.txt")
	_, hasPyproject := os.Stat(dir + "/pyproject.toml")
	if hasReqs == nil || hasPyproject == nil {
		if !isAvailable("pip-audit") {
			skipped = append(skipped, SkippedTool{
				Tool:        "pip-audit",
				InstallHint: "pip install pip-audit",
			})
		} else {
			progress("[devsec] running pip-audit...")
			start := time.Now()
			output, err := runTool(120, "pip-audit", "--path", dir, "--format", "json")
			tr := ToolResult{
				Tool:   "pip-audit",
				Output: stripANSI(output),
				Took:   time.Since(start),
			}
			if err != nil {
				tr.Error = err.Error()
			}
			results = append(results, tr)
		}
	}

	return results, skipped
}

// ─── Combined Output ──────────────────────────────────────────────────────────

// buildCombinedRaw assembles all phase results into a single ANSI-stripped string.
func buildCombinedRaw(result *DevSecResult) string {
	var b strings.Builder

	writePhase := func(label string, results []ToolResult) {
		for _, tr := range results {
			if tr.Output != "" {
				b.WriteString(fmt.Sprintf("=== %s — %s ===\n%s\n\n",
					label, strings.ToUpper(tr.Tool), tr.Output))
			}
		}
	}

	writePhase("PHASE 1 (SECRETS)", result.Phase1)
	writePhase("PHASE 2 (SAST)", result.Phase2)
	writePhase("PHASE 3 (DEPS)", result.Phase3)

	return b.String()
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunDevSec executes the full DevSec pipeline.
// target: GitHub URL (https://github.com/owner/repo) or local path.
// progress: callback for live status updates.
func RunDevSec(target string, progress func(string)) (DevSecResult, error) {
	result := DevSecResult{Target: target}

	// Resolve scan directory
	scanDir := target
	if isGitHubURL(target) {
		progress(fmt.Sprintf("[devsec] cloning %s...", target))
		tmpDir, err := cloneRepo(target)
		if err != nil {
			return result, fmt.Errorf("clone failed: %w", err)
		}
		defer os.RemoveAll(tmpDir)
		scanDir = tmpDir
	}

	// Phase 1 — Secret scanning
	progress("[devsec] phase 1: secret scanning...")
	p1Results, p1Skipped := runPhase1(scanDir, progress)
	result.Phase1 = p1Results
	result.Skipped = append(result.Skipped, p1Skipped...)

	// Phase 2 — SAST
	progress("[devsec] phase 2: SAST...")
	p2Results, p2Skipped := runPhase2(scanDir, progress)
	result.Phase2 = p2Results
	result.Skipped = append(result.Skipped, p2Skipped...)

	// Phase 3 — Dependency audit
	progress("[devsec] phase 3: dependency audit...")
	p3Results, p3Skipped := runPhase3(scanDir, progress)
	result.Phase3 = p3Results
	result.Skipped = append(result.Skipped, p3Skipped...)

	// Build combined raw output (ANSI-stripped) for backend
	result.CombinedRaw = buildCombinedRaw(&result)

	// POST findings to backend for AI analysis
	progress("[devsec] sending findings to AI for analysis...")
	analysis, err := api.SendDevSecAnalyze(target, result.CombinedRaw)
	if err != nil {
		progress(fmt.Sprintf("[devsec] AI analysis failed: %s", err.Error()))
		// Save raw findings to Brain_Memory even if AI analysis fails
		_ = storage.AddEntry("/devsec "+target, result.CombinedRaw)
		return result, nil
	}

	// Save result to Brain_Memory
	_ = storage.AddEntry("/devsec "+target, analysis)

	// Print the AI analysis result
	printResult(analysis)

	return result, nil
}

// printResult displays the AI analysis result to the terminal.
func printResult(analysis string) {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════╗")
	fmt.Println("  ║              🔐 DevSec AI Analysis                      ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println(analysis)
	fmt.Println()
}
