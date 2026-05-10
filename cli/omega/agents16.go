// omega/agents16.go — 16-Agent OMEGA Integration
// Adds RunOmegaPlan16 which uses brain.RunAgents for parallel execution.
// Called from commands.go when --agents flag is used or plan mode is "deep"/"overnight".
package omega

import (
"fmt"
"strings"
"sync"
"time"

"cybermind-cli/api"
"cybermind-cli/brain"
"cybermind-cli/utils"

"github.com/charmbracelet/lipgloss"
)

// RunOmegaPlan16 runs the 16-agent parallel OMEGA pipeline.
// This is the upgraded version of RunOmegaPlan that uses specialist agents.
func RunOmegaPlan16(target, mode, plan string, continuous bool) {
s := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF"))
d := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))
g := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
y := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))

fmt.Println()
fmt.Println(s.Render("  ⚡ OMEGA v2 — 16-Agent Parallel Attack Pipeline"))
fmt.Println(d.Render("  " + strings.Repeat("─", 60)))
fmt.Printf("  Target: %s | Mode: %s | Plan: %s\n\n",
s.Render(target), y.Render(mode), g.Render(plan))

// Load memory + knowledge graph
mem := brain.LoadTarget(target)
fmt.Println(brain.GetMemorySummary(target))
fmt.Println(brain.GetGraphSummary(target))

// Build reasoning session from memory
session := brain.NewReasoningSession(target, mode)
profile := brain.TargetProfile{
Target:      target,
TechStack:   mem.TechStack,
WAFDetected: mem.WAFDetected,
WAFVendor:   mem.WAFVendor,
OpenPorts:   mem.OpenPorts,
Patterns:    brain.GetBestPatterns(target),
}
branches := brain.BuildBranchesFromProfile(profile)
session.Branches = branches

// Show attack plan
fmt.Println(brain.FormatBranchPlan(brain.TopBranches(branches, 8)))

// Select agents for this mode + plan
agents := brain.SelectAgentsForMode(mode, plan, mem)
brain.PrintAgentPlan(agents)

if len(agents) == 0 {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444")).Render(
"  ✗ No agents available for this mode/plan. Install tools first: cybermind /doctor"))
return
}

// Run agents in parallel with live multi-TUI
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
fmt.Sprintf("  ⟳ Running %d agents in parallel...", len(agents))))
fmt.Println()

var mu sync.Mutex
lastRender := time.Now()

results := brain.RunAgents(target, agents, mem, func(panels []*brain.AgentPanel) {
mu.Lock()
defer mu.Unlock()
if time.Since(lastRender) < 300*time.Millisecond {
return
}
lastRender = time.Now()
renderAgentGrid(panels)
})

// Collect all findings
var allBugs []brain.Bug
for _, r := range results {
allBugs = append(allBugs, r.Findings...)
}

// Update memory + knowledge graph
brain.RecordRun(target, mem.TechStack, mem.WAFVendor, mem.WAFDetected,
mem.SubdomainsFound, mem.LiveURLs, mem.OpenPorts)
brain.RecordTargetInGraph(target, mem)

// Print reasoning summary
fmt.Println(session.ReasoningSummary())

// AI synthesis
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render(
"  ⟳ AI synthesizing all agent findings..."))
synthesizeAgentFindings(target, allBugs, results)

// Summary
fmt.Println()
if len(allBugs) > 0 {
fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4444")).Render(
fmt.Sprintf("  🔴 %d vulnerabilities found across %d agents!", len(allBugs), len(agents))))
for _, b := range allBugs {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Render(
fmt.Sprintf("    [%s] %s — %s", strings.ToUpper(b.Severity), b.Title, b.URL)))
}
} else {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render(
"  ✓ No critical vulnerabilities found. Try: cybermind /plan " + target + " --mode deep"))
}

if continuous {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(
"  ↻ Continuous mode — restarting in 60s..."))
time.Sleep(60 * time.Second)
RunOmegaPlan16(target, mode, plan, continuous)
}
}

// renderAgentGrid renders all agent panels in a grid layout
func renderAgentGrid(panels []*brain.AgentPanel) {
fmt.Print("\033[H\033[2J") // clear terminal
cols := 3
if len(panels) <= 4 {
cols = 2
}
colWidth := 58

for i := 0; i < len(panels); i += cols {
row := panels[i:]
if len(row) > cols {
row = row[:cols]
}
rendered := make([][]string, len(row))
maxLines := 0
for j, p := range row {
text := p.Render(colWidth)
lines := strings.Split(text, "\n")
rendered[j] = lines
if len(lines) > maxLines {
maxLines = len(lines)
}
}
for line := 0; line < maxLines; line++ {
for j := range row {
var l string
if line < len(rendered[j]) {
l = rendered[j][line]
}
for len(l) < colWidth {
l += " "
}
if len(l) > colWidth {
l = l[:colWidth]
}
fmt.Print(l)
if j < len(row)-1 {
fmt.Print(" | ")
}
}
fmt.Println()
}
fmt.Println(strings.Repeat("─", colWidth*cols+3*(cols-1)))
}
}

// synthesizeAgentFindings sends all findings to AI for synthesis
func synthesizeAgentFindings(target string, bugs []brain.Bug, results []brain.AgentResult) {
graphCtx := brain.GetGraphContext(target)
memCtx := brain.GetLearnedPromptContext(target)

var sb strings.Builder
sb.WriteString(fmt.Sprintf("OMEGA 16-agent scan complete for %s.\n\n", target))
sb.WriteString(graphCtx)
sb.WriteString(memCtx)
sb.WriteString(fmt.Sprintf("\nAGENT RESULTS (%d agents):\n", len(results)))
for _, r := range results {
if r.Status == brain.AgentDone {
sb.WriteString(fmt.Sprintf("- [%s] %s: %d findings\n", r.AgentID, r.Name, len(r.Findings)))
}
}
if len(bugs) > 0 {
sb.WriteString(fmt.Sprintf("\nCONFIRMED BUGS (%d):\n", len(bugs)))
for _, b := range bugs {
sb.WriteString(fmt.Sprintf("- [%s] %s at %s\n", strings.ToUpper(b.Severity), b.Title, b.URL))
}
}
sb.WriteString("\nProvide: attack chain analysis, exploitation priority, MITRE ATT&CK mapping, remediation.")

result, err := api.SendPrompt(sb.String())
if err != nil {
return
}
clean := utils.StripMarkdown(result)
fmt.Println()
fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render("  ⚡ OMEGA AI Synthesis"))
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("─", 60)))
for _, line := range strings.Split(clean, "\n") {
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).Render("  " + line))
}
}
