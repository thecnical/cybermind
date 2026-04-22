// Package reveng — CyberMind Reverse Engineering Mode
// Linux-only. Full automated RE pipeline.
//
// Usage:
//   cybermind /reveng <binary>                 — full RE (auto-detect file type)
//   cybermind /reveng <binary> --mode static   — static analysis only
//   cybermind /reveng <binary> --mode dynamic  — dynamic (strace/frida/gdb)
//   cybermind /reveng <binary> --mode decompile — decompile + AI explain
//   cybermind /reveng <binary> --mode malware  — malware analysis
//   cybermind /reveng <binary> --mode mobile   — APK/IPA analysis
//   cybermind /reveng <binary> --tools r2,checksec — specific tools
//
// Phases:
//   Phase 1 — File ID + Metadata (file, sha256sum, strings, readelf, objdump, exiftool)
//   Phase 2 — Static Analysis (checksec, radare2, rizin, binwalk, nm, ldd, floss, die)
//   Phase 3 — Dynamic Analysis (strace, ltrace, gdb+pwndbg, frida, r2frida, QEMU, unicorn)
//   Phase 4 — Vulnerability Discovery (ROPgadget, pwntools, angr, cve-bin-tool)
//   Phase 5 — Malware Analysis (yara, ssdeep, clamscan, die)
//   Phase 6 — Decompilation (Ghidra headless, retdec, jadx, apktool, r2ghidra)
package reveng

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

type RevEngResult struct {
	Target   string
	FileType string
	Results  []RevEngToolResult
	Tools    []string
	Failed   []RevEngToolResult
	Skipped  []RevEngSkipped
	Context  *RevEngContext
}

type RevEngToolResult struct {
	Tool    string
	Output  string
	Error   string
	Partial bool
	Took    time.Duration
}

type RevEngSkipped struct {
	Tool        string
	Reason      string
	InstallHint string
}

type RevEngStatusKind string

const (
	RevEngRunning     RevEngStatusKind = "running"
	RevEngDone        RevEngStatusKind = "done"
	RevEngFailed      RevEngStatusKind = "failed"
	RevEngKindSkipped RevEngStatusKind = "skipped"
	RevEngPartial     RevEngStatusKind = "partial"
	RevEngRetry       RevEngStatusKind = "retry"
)

type RevEngStatus struct {
	Tool   string
	Kind   RevEngStatusKind
	Reason string
	Took   time.Duration
}

type RevEngContext struct {
	Target       string
	AnalysisMode string // "all"|"static"|"dynamic"|"decompile"|"malware"|"mobile"
	FileType     string // "elf"|"pe"|"apk"|"firmware"|"macho"|"jar"
	Architecture string // "x86_64"|"x86"|"arm64"|"arm"|"mips"
	Bitness      string // "32"|"64"
	Stripped     bool
	PIE          bool
	NX           bool
	Canary       bool
	RELRO        string

	// Findings
	SuspiciousStrings []string
	NetworkIndicators []string
	ImportedLibs      []string
	ExportedFuncs     []string
	VulnFunctions     []string
	YARAMatches       []string
	ROPGadgets        []string
	EntryPoint        string
	MD5Hash           string
	SHA256Hash        string

	// Session
	SessionDir   string
	DecompileDir string
	StartedAt    time.Time
}

type RevEngSession struct {
	Target        string            `json:"target"`
	AnalysisMode  string            `json:"analysis_mode"`
	FileType      string            `json:"file_type"`
	Architecture  string            `json:"architecture"`
	StartedAt     time.Time         `json:"started_at"`
	ToolsRun      []string          `json:"tools_run"`
	Findings      map[string]string `json:"findings"`
	VulnFunctions []string          `json:"vuln_functions"`
	YARAMatches   []string          `json:"yara_matches"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var ansiReRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func sanitizeRE(s string, maxLen int) string {
	clean := ansiReRE.ReplaceAllString(s, "")
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

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

func runShell(timeoutSec int, shellCmd string) (string, error) {
	return run(timeoutSec, "bash", "-c", shellCmd)
}

func dedupRE(items []string) []string {
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

func containsStrRE(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// getPhasesForMode returns which phases to run for a given analysis mode.
func getPhasesForMode(mode string) []int {
	switch mode {
	case "static":
		return []int{1, 2}
	case "dynamic":
		return []int{1, 3}
	case "decompile":
		return []int{1, 6}
	case "malware":
		return []int{1, 2, 5}
	case "mobile":
		return []int{1, 6}
	default: // "all"
		return []int{1, 2, 3, 4, 5, 6}
	}
}

// ─── Context Extraction ───────────────────────────────────────────────────────

func updateRevEngContext(tool, output string, ctx *RevEngContext) {
	lines := strings.Split(output, "\n")
	switch tool {
	case "file":
		ctx.FileType = strings.TrimSpace(output)
		lower := strings.ToLower(output)
		if strings.Contains(lower, "x86-64") || strings.Contains(lower, "x86_64") {
			ctx.Architecture = "x86_64"; ctx.Bitness = "64"
		} else if strings.Contains(lower, "80386") || strings.Contains(lower, "i386") {
			ctx.Architecture = "x86"; ctx.Bitness = "32"
		} else if strings.Contains(lower, "aarch64") || strings.Contains(lower, "arm64") {
			ctx.Architecture = "arm64"; ctx.Bitness = "64"
		} else if strings.Contains(lower, "arm") {
			ctx.Architecture = "arm"; ctx.Bitness = "32"
		} else if strings.Contains(lower, "mips") {
			ctx.Architecture = "mips"
		}
		if strings.Contains(lower, "stripped") {
			ctx.Stripped = true
		}
		if strings.Contains(lower, "elf") && ctx.FileType == "" {
			ctx.FileType = "elf"
		} else if strings.Contains(lower, "pe32") || strings.Contains(lower, "ms-dos") {
			ctx.FileType = "pe"
		} else if strings.Contains(lower, "mach-o") {
			ctx.FileType = "macho"
		} else if strings.Contains(lower, "zip") || strings.Contains(lower, "apk") {
			ctx.FileType = "apk"
		}

	case "checksec":
		lower := strings.ToLower(output)
		ctx.PIE = strings.Contains(lower, "pie enabled")
		ctx.NX = strings.Contains(lower, "nx enabled")
		ctx.Canary = strings.Contains(lower, "canary found")
		if strings.Contains(lower, "full relro") {
			ctx.RELRO = "full"
		} else if strings.Contains(lower, "partial relro") {
			ctx.RELRO = "partial"
		} else {
			ctx.RELRO = "none"
		}

	case "strings":
		suspicious := []string{
			"password", "passwd", "secret", "key", "token", "api",
			"http://", "https://", "ftp://", "/etc/passwd", "/etc/shadow",
			"cmd.exe", "powershell", "bash -i", "sh -c", "exec(",
			"SELECT", "DROP TABLE", "UNION", "base64", "eval(",
			"system(", "popen(", "wget ", "curl ",
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if len(line) < 4 {
				continue
			}
			lower := strings.ToLower(line)
			for _, p := range suspicious {
				if strings.Contains(lower, strings.ToLower(p)) {
					ctx.SuspiciousStrings = dedupRE(append(ctx.SuspiciousStrings, line))
					break
				}
			}
			if strings.Contains(line, "://") || strings.Contains(line, ".onion") {
				ctx.NetworkIndicators = dedupRE(append(ctx.NetworkIndicators, line))
			}
		}

	case "readelf":
		for _, line := range lines {
			if strings.Contains(line, "NEEDED") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ctx.ImportedLibs = dedupRE(append(ctx.ImportedLibs, parts[len(parts)-1]))
				}
			}
			if strings.Contains(line, "Entry point") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ctx.EntryPoint = parts[len(parts)-1]
				}
			}
		}

	case "objdump":
		dangerous := []string{"strcpy", "strcat", "gets", "sprintf", "scanf", "system", "popen", "execve"}
		for _, line := range lines {
			if strings.Contains(line, "<") && strings.Contains(line, ">:") {
				start := strings.Index(line, "<")
				end := strings.Index(line, ">:")
				if start >= 0 && end > start {
					funcName := line[start+1 : end]
					for _, d := range dangerous {
						if strings.Contains(strings.ToLower(funcName), d) {
							ctx.VulnFunctions = dedupRE(append(ctx.VulnFunctions, funcName))
						}
					}
					ctx.ExportedFuncs = dedupRE(append(ctx.ExportedFuncs, funcName))
				}
			}
		}

	case "yara":
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "//") {
				ctx.YARAMatches = dedupRE(append(ctx.YARAMatches, line))
			}
		}

	case "ROPgadget":
		for _, line := range lines {
			if strings.Contains(line, "0x") && strings.Contains(line, ":") {
				ctx.ROPGadgets = dedupRE(append(ctx.ROPGadgets, strings.TrimSpace(line)))
				if len(ctx.ROPGadgets) >= 50 {
					break
				}
			}
		}
	}
}

// ─── Tool Detection ───────────────────────────────────────────────────────────

var lookPathRE = exec.LookPath

func detectRevEngTools(requested []string) (available []RevEngToolSpec, skipped []RevEngSkipped, err error) {
	if requested != nil {
		validSet := make(map[string]bool)
		for _, s := range revEngRegistry {
			validSet[s.Name] = true
		}
		for _, name := range requested {
			if !validSet[name] {
				return nil, nil, fmt.Errorf("unknown RE tool %q — valid: %s",
					name, strings.Join(RevEngToolNames(), ", "))
			}
		}
	}

	for _, spec := range revEngRegistry {
		if requested != nil && !containsStrRE(requested, spec.Name) {
			skipped = append(skipped, RevEngSkipped{Tool: spec.Name, Reason: "not in --tools list"})
			continue
		}
		_, err := lookPathRE(spec.Name)
		if err != nil {
			found := false
			for _, alt := range spec.AltPaths {
				if _, e := os.Stat(alt); e == nil {
					found = true
					break
				}
			}
			if !found {
				skipped = append(skipped, RevEngSkipped{
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

func runRevEngToolExhaustive(spec RevEngToolSpec, target string, ctx *RevEngContext, progress func(RevEngStatus)) (string, error) {
	var output string
	var err error

	if spec.UseShell {
		shellCmd := spec.ShellCmd(target, ctx)
		if shellCmd == "" {
			return "", fmt.Errorf("no shell command for this target")
		}
		output, err = runShell(spec.Timeout, shellCmd)
	} else {
		args := spec.BuildArgs(target, ctx)
		if len(args) == 0 {
			return "", fmt.Errorf("not applicable for this target")
		}
		output, err = run(spec.Timeout, spec.Name, args...)
	}

	if strings.TrimSpace(output) != "" {
		return output, err
	}

	for i, fallbackFn := range spec.FallbackArgs {
		progress(RevEngStatus{
			Tool:   spec.Name,
			Kind:   RevEngRetry,
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

func addRevEngResult(result *RevEngResult, spec RevEngToolSpec, output string, err error, took time.Duration) {
	tr := RevEngToolResult{Tool: spec.Name, Took: took}
	if output != "" {
		tr.Output = sanitizeRE(output, 200000)
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

func saveRevEngSession(ctx *RevEngContext, findings map[string]string) {
	if ctx.SessionDir == "" {
		return
	}
	toolsRun := make([]string, 0, len(findings))
	for t := range findings {
		toolsRun = append(toolsRun, t)
	}
	session := RevEngSession{
		Target:        ctx.Target,
		AnalysisMode:  ctx.AnalysisMode,
		FileType:      ctx.FileType,
		Architecture:  ctx.Architecture,
		StartedAt:     ctx.StartedAt,
		ToolsRun:      toolsRun,
		Findings:      findings,
		VulnFunctions: ctx.VulnFunctions,
		YARAMatches:   ctx.YARAMatches,
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(ctx.SessionDir+"/session.json", data, 0600)
}

func loadRevEngSession(sessionDir string) *RevEngSession {
	data, err := os.ReadFile(sessionDir + "/session.json")
	if err != nil {
		return nil
	}
	var session RevEngSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil
	}
	return &session
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunRevEng executes the full RE pipeline against a binary/file.
func RunRevEng(target string, mode string, requested []string, progress func(RevEngStatus)) RevEngResult {
	result := RevEngResult{Target: target}

	// Validate file exists
	if _, err := os.Stat(target); err != nil {
		result.Skipped = append(result.Skipped, RevEngSkipped{Tool: "all", Reason: "file not found: " + target})
		return result
	}

	if mode == "" {
		mode = "all"
	}

	ctx := &RevEngContext{
		Target:       target,
		AnalysisMode: mode,
		StartedAt:    time.Now(),
	}

	// Setup session directory
	safe := strings.NewReplacer("/", "_", ".", "_", " ", "_", "\\", "_").Replace(target)
	if len(safe) > 50 {
		safe = safe[len(safe)-50:]
	}
	ctx.SessionDir = fmt.Sprintf("/tmp/cybermind_reveng_%s", safe)
	ctx.DecompileDir = ctx.SessionDir + "/decompile"
	os.MkdirAll(ctx.SessionDir, 0700)
	os.MkdirAll(ctx.DecompileDir, 0700)

	// Load previous session
	prev := loadRevEngSession(ctx.SessionDir)
	if prev != nil {
		ctx.FileType = prev.FileType
		ctx.Architecture = prev.Architecture
		ctx.VulnFunctions = prev.VulnFunctions
		ctx.YARAMatches = prev.YARAMatches
	}

	available, skipped, err := detectRevEngTools(requested)
	if err != nil {
		result.Skipped = append(result.Skipped, RevEngSkipped{Tool: "all", Reason: err.Error()})
		return result
	}
	result.Skipped = skipped

	for _, s := range skipped {
		progress(RevEngStatus{Tool: s.Tool, Kind: RevEngKindSkipped, Reason: s.Reason})
	}

	findings := make(map[string]string)
	phases := getPhasesForMode(mode)

	for _, phase := range phases {
		for _, spec := range available {
			if spec.Phase != phase {
				continue
			}
			// Filter by target type if context has file type
			if len(spec.TargetTypes) > 0 && ctx.FileType != "" {
				match := false
				for _, tt := range spec.TargetTypes {
					if tt == "all" || tt == ctx.FileType {
						match = true
						break
					}
				}
				if !match {
					result.Skipped = append(result.Skipped, RevEngSkipped{
						Tool:   spec.Name,
						Reason: fmt.Sprintf("not applicable for %s binaries", ctx.FileType),
					})
					progress(RevEngStatus{Tool: spec.Name, Kind: RevEngKindSkipped,
						Reason: fmt.Sprintf("not for %s", ctx.FileType)})
					continue
				}
			}

			progress(RevEngStatus{Tool: spec.Name, Kind: RevEngRunning})
			start := time.Now()
			output, runErr := runRevEngToolExhaustive(spec, target, ctx, progress)
			took := time.Since(start)

			addRevEngResult(&result, spec, output, runErr, took)

			last := result.Results[len(result.Results)-1]
			var kind RevEngStatusKind
			switch {
			case last.Partial:
				kind = RevEngPartial
			case last.Error != "" && last.Output == "":
				kind = RevEngFailed
			default:
				kind = RevEngDone
			}
			progress(RevEngStatus{Tool: spec.Name, Kind: kind, Took: took, Reason: last.Error})

			if output != "" {
				findings[spec.Name] = output
				updateRevEngContext(spec.Name, output, ctx)
				saveRevEngSession(ctx, findings)
			}
		}
	}

	result.FileType = ctx.FileType
	result.Context = ctx
	return result
}

// RevEngToolNames returns all tool names in the RE registry.
func RevEngToolNames() []string {
	names := make([]string, len(revEngRegistry))
	for i, s := range revEngRegistry {
		names[i] = s.Name
	}
	return names
}

// GetRevEngCombinedOutput returns all tool outputs as one string.
func GetRevEngCombinedOutput(r RevEngResult) string {
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
		}
	}
	return b.String()
}
