package chain

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/brain"
	"github.com/charmbracelet/lipgloss"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// ChainResult holds the exploit chains returned by the backend.
type ChainResult struct {
	Target string
	Chains []ExploitChain
	Model  string
}

// ExploitChain represents a single multi-step exploit chain.
type ExploitChain struct {
	ID         int
	Vulns      []string
	Impact     string
	PoC        string
	CVSSUplift float64
}

// ─── Lipgloss Styles ──────────────────────────────────────────────────────────

var (
	cyanStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	redStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	boldStyle   = lipgloss.NewStyle().Bold(true)
	headerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
)

// ─── Bug Extraction ───────────────────────────────────────────────────────────

// extractBugs converts brain.Bug slice to a slice of maps for the API payload.
func extractBugs(bugs []brain.Bug) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(bugs))
	for _, b := range bugs {
		entry := map[string]interface{}{
			"id":       b.ID,
			"title":    b.Title,
			"type":     b.Type,
			"url":      b.URL,
			"severity": b.Severity,
			"evidence": b.Evidence,
			"poc":      b.PoC,
			"tool":     b.Tool,
			"verified": b.Verified,
		}
		if b.CVE != "" {
			entry["cve"] = b.CVE
		}
		result = append(result, entry)
	}
	return result
}

// ─── Chain Display Formatting ─────────────────────────────────────────────────

// formatChainLine formats a single chain summary line.
// Output: "Chain N: <vuln1> + <vuln2> -> <impact>"
func formatChainLine(id int, vulns []string, impact string) string {
	vulnStr := strings.Join(vulns, " + ")
	return fmt.Sprintf("Chain %d: %s -> %s", id, vulnStr, impact)
}

// parseChainLines parses the AI text response to extract chain display lines.
// The backend returns free-form text; we look for "Chain N:" patterns.
func parseChainLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Chain ") {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunChain loads Brain_Memory for target, sends bugs to backend, displays chains.
func RunChain(target string) error {
	// ── Step 1: Load Brain_Memory ────────────────────────────────────────────
	mem := brain.LoadTarget(target)
	bugs := mem.BugsFound

	// ── Step 2: Check minimum bug count ─────────────────────────────────────
	if len(bugs) < 2 {
		fmt.Println(redStyle.Render("  Not enough findings in memory. Run /recon and /hunt first."))
		return nil
	}

	// ── Display header ───────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(boldStyle.Render("  ╔══════════════════════════════════════════════════════════╗"))
	fmt.Println(boldStyle.Render("  ║           ⛓  Chain — Vulnerability Chaining Engine       ║"))
	fmt.Println(boldStyle.Render("  ╚══════════════════════════════════════════════════════════╝"))
	fmt.Printf("  Target: %s\n", cyanStyle.Render(target))
	fmt.Printf("  Bugs in memory: %s\n\n", cyanStyle.Render(strconv.Itoa(len(bugs))))

	// ── Step 3: Convert bugs to map format ───────────────────────────────────
	bugMaps := extractBugs(bugs)

	// ── Step 4: POST to backend ──────────────────────────────────────────────
	fmt.Println(cyanStyle.Render("  [chain] Analyzing exploit chains with AI..."))
	analysis, err := api.SendChainAnalyze(target, bugMaps)
	if err != nil {
		fmt.Printf("  %s\n", redStyle.Render(fmt.Sprintf("[chain] AI analysis failed: %s", err.Error())))
		return err
	}

	// ── Step 5: Display AI response ──────────────────────────────────────────
	fmt.Println()
	fmt.Println(headerStyle.Render("  ─── Exploit Chain Analysis ───────────────────────────────"))
	fmt.Println()

	// Print the full AI analysis
	for _, line := range strings.Split(analysis, "\n") {
		if strings.TrimSpace(line) == "" {
			fmt.Println()
			continue
		}
		// Highlight chain header lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Chain ") {
			fmt.Printf("  %s\n", greenStyle.Render(trimmed))
		} else {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Println()

	// ── Step 6: Prompt user to select a chain ────────────────────────────────
	// Extract chain lines to determine how many chains were returned
	chainLines := parseChainLines(analysis)
	numChains := len(chainLines)

	if numChains == 0 {
		// No structured chains found — display raw analysis only
		fmt.Println(cyanStyle.Render("  [chain] No structured chains detected in response. Showing raw analysis above."))
		return nil
	}

	fmt.Println(headerStyle.Render("  ─── Chain Selection ──────────────────────────────────────"))
	fmt.Println()
	fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("Enter chain number (1-%d) to execute, or press Enter to skip:", numChains)))
	fmt.Print("  > ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	// ── Step 7: Handle chain selection ───────────────────────────────────────
	if input == "" {
		fmt.Println()
		fmt.Println(cyanStyle.Render("  [chain] Skipping execution. Analysis saved to Brain_Memory."))
		// Save analysis to Brain_Memory even when skipping
		brain.RecordBug(target, brain.Bug{
			Title:    fmt.Sprintf("Chain Analysis — %s", target),
			Type:     "chain_analysis",
			URL:      target,
			Severity: "info",
			Evidence: analysis,
			PoC:      analysis,
			Tool:     "chain",
			Verified: false,
		})
		return nil
	}

	selectedNum, err := strconv.Atoi(input)
	if err != nil || selectedNum < 1 || selectedNum > numChains {
		fmt.Printf("  %s\n", redStyle.Render(fmt.Sprintf("[chain] Invalid selection %q — must be 1-%d", input, numChains)))
		return nil
	}

	// ── Step 8: Execute selected chain ───────────────────────────────────────
	selectedLine := chainLines[selectedNum-1]
	fmt.Println()
	fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("[chain] Executing: %s", selectedLine)))
	fmt.Println()

	// Extract PoC steps for the selected chain from the analysis text
	pocSteps := extractPoCForChain(analysis, selectedNum)

	if pocSteps != "" {
		fmt.Println(headerStyle.Render("  ─── PoC Steps ────────────────────────────────────────────"))
		fmt.Println()
		for _, step := range strings.Split(pocSteps, "\n") {
			if strings.TrimSpace(step) != "" {
				fmt.Printf("  %s\n", step)
			}
		}
		fmt.Println()
	}

	// Simulate chain execution — stream output to terminal
	fmt.Println(cyanStyle.Render("  [chain] Running chain-specific tools..."))
	runChainToolsReal(target, selectedLine, bugs)

	// ── Step 9: Save chain result and PoC to Brain_Memory ────────────────────
	chainPoC := pocSteps
	if chainPoC == "" {
		chainPoC = analysis
	}

	brain.RecordBug(target, brain.Bug{
		ID:       fmt.Sprintf("chain_%d_%d", selectedNum, time.Now().UnixNano()),
		Title:    fmt.Sprintf("Exploit Chain %d: %s", selectedNum, selectedLine),
		Type:     "exploit_chain",
		URL:      target,
		Severity: "high",
		Evidence: selectedLine,
		PoC:      chainPoC,
		Tool:     "chain",
		Verified: false,
	})

	fmt.Println()
	fmt.Println(greenStyle.Render("  [chain] Chain result and PoC saved to Brain_Memory."))

	return nil
}

// ─── PoC Extraction ───────────────────────────────────────────────────────────

// extractPoCForChain extracts the PoC steps for a specific chain number from the AI text.
// Looks for content between "Chain N:" and the next "Chain" header or end of text.
func extractPoCForChain(text string, chainNum int) string {
	lines := strings.Split(text, "\n")
	var pocLines []string
	inChain := false
	chainPrefix := fmt.Sprintf("Chain %d:", chainNum)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, chainPrefix) {
			inChain = true
			continue
		}

		// Stop at the next chain header
		if inChain && strings.HasPrefix(trimmed, "Chain ") && !strings.HasPrefix(trimmed, chainPrefix) {
			break
		}

		if inChain && trimmed != "" {
			pocLines = append(pocLines, line)
		}
	}

	return strings.Join(pocLines, "\n")
}

// ─── Chain Tool Runner ────────────────────────────────────────────────────────

// runChainTools runs real tools for each vuln type in the chain.
// Uses actual security tools — no fake sleep.
func runChainTools(target string, chainLine string) {
	vulnTypes := extractVulnTypes(chainLine)
	baseURL := target
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "https://" + target
	}

	fmt.Println()
	for i, vuln := range vulnTypes {
		fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[%d/%d] Executing %s on %s...", i+1, len(vulnTypes), vuln, target)))

		lower := strings.ToLower(vuln)
		var out []byte
		var err error

		switch {
		case strings.Contains(lower, "xss"):
			if _, e := exec.LookPath("dalfox"); e == nil {
				cmd := exec.Command("dalfox", "url", baseURL, "--silence", "--no-color", "--waf-bypass")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql"):
			if _, e := exec.LookPath("sqlmap"); e == nil {
				cmd := exec.Command("sqlmap", "-u", baseURL+"/?id=1",
					"--level=2", "--risk=1", "--batch", "--random-agent",
					"--output-dir=/tmp/cybermind_chain")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "ssrf"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "ssrf,oast", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "idor"):
			if _, e := exec.LookPath("ffuf"); e == nil {
				cmd := exec.Command("ffuf", "-u", baseURL+"/api/user/FUZZ",
					"-w", "/usr/share/seclists/Fuzzing/4-digits-0000-9999.txt",
					"-mc", "200", "-silent")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "lfi") || strings.Contains(lower, "path"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "lfi,path-traversal", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "rce") || strings.Contains(lower, "command"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "rce,command-injection", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		case strings.Contains(lower, "auth") || strings.Contains(lower, "bypass"):
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-t", "auth-bypass,default-logins", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		default:
			// Generic nuclei scan for unknown vuln type
			if _, e := exec.LookPath("nuclei"); e == nil {
				cmd := exec.Command("nuclei", "-u", baseURL, "-severity", "critical,high", "-silent", "-no-color")
				out, err = cmd.Output()
			}
		}

		if err == nil && len(out) > 0 {
			output := strings.TrimSpace(string(out))
			if output != "" {
				lines := strings.Split(output, "\n")
				shown := 0
				for _, l := range lines {
					if strings.TrimSpace(l) != "" && shown < 5 {
						fmt.Printf("      %s\n", l)
						shown++
					}
				}
			}
			fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("  ✓ %s execution complete", vuln)))
		} else {
			fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("  – %s: tool not available or no output", vuln)))
		}
	}
	fmt.Println()
	fmt.Println(greenStyle.Render("  [chain] Chain execution complete."))
}

// extractVulnTypes parses vuln type names from a chain line.
// Input: "Chain 1: SSRF + IDOR -> PII leak via internal API pivot"
// Output: ["SSRF", "IDOR"]
func extractVulnTypes(chainLine string) []string {
	// Find the part between "Chain N: " and " -> "
	arrowIdx := strings.Index(chainLine, "->")
	if arrowIdx < 0 {
		arrowIdx = strings.Index(chainLine, "→")
	}

	colonIdx := strings.Index(chainLine, ":")
	if colonIdx < 0 || arrowIdx < 0 {
		return []string{"vulnerability"}
	}

	vulnPart := strings.TrimSpace(chainLine[colonIdx+1 : arrowIdx])
	parts := strings.Split(vulnPart, "+")
	var vulns []string
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			vulns = append(vulns, v)
		}
	}
	if len(vulns) == 0 {
		return []string{"vulnerability"}
	}
	return vulns
}

// runChainToolsReal runs REAL tools for each vuln type in the chain.
func runChainToolsReal(target string, chainLine string, bugs []brain.Bug) {
vulnTypes := extractVulnTypes(chainLine)
baseURL := "https://" + target
if strings.HasPrefix(target, "http") {
baseURL = target
}

fmt.Println()
for i, vuln := range vulnTypes {
fmt.Printf("  %s\n", cyanStyle.Render(fmt.Sprintf("[%d/%d] Executing %s on %s...", i+1, len(vulnTypes), vuln, target)))
lower := strings.ToLower(vuln)
switch {
case strings.Contains(lower, "xss"):
runChainTool("dalfox", "url", baseURL, "--silence", "--no-color", "--waf-bypass")
case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql"):
sqlURL := baseURL
for _, b := range bugs {
if strings.Contains(strings.ToLower(b.Type), "sqli") {
sqlURL = b.URL
break
}
}
runChainTool("sqlmap", "-u", sqlURL, "--level=3", "--risk=2", "--batch", "--random-agent", "--dbs")
case strings.Contains(lower, "ssrf"):
runChainTool("nuclei", "-u", baseURL, "-t", "ssrf", "-severity", "critical,high", "-silent", "-no-color")
case strings.Contains(lower, "rce"):
runChainTool("commix", "--url", baseURL, "--batch", "--level=3")
default:
runChainTool("nuclei", "-u", baseURL, "-severity", "critical,high", "-silent", "-no-color")
}
fmt.Printf("  %s\n", greenStyle.Render(fmt.Sprintf("  \u2713 %s step complete", vuln)))
}
fmt.Println()
fmt.Println(greenStyle.Render("  [chain] Chain execution complete."))
}

// runChainTool runs a single tool with live output
func runChainTool(name string, args ...string) {
if _, err := exec.LookPath(name); err != nil {
fmt.Printf("  [chain] %s not installed \u2014 skipping\n", name)
return
}
cmd := exec.Command(name, args...)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
cmd.Run()
}
