package brain

import (
"fmt"
"strings"
"sync"
"time"

"github.com/charmbracelet/lipgloss"
)

type AgentStatus string

const (
AgentPending AgentStatus = "pending"
AgentRunning AgentStatus = "running"
AgentDone    AgentStatus = "done"
AgentFailed  AgentStatus = "failed"
AgentSkipped AgentStatus = "skipped"
)

type AgentResult struct {
AgentID  AgentRole
Name     string
Status   AgentStatus
Output   string
Findings []Bug
Lines    []string
Duration time.Duration
Error    string
}

type AgentPanel struct {
AgentID  AgentRole
Name     string
Status   AgentStatus
Lines    []string
Findings int
mu       sync.Mutex
}

func (p *AgentPanel) AddLine(line string) {
p.mu.Lock()
defer p.mu.Unlock()
p.Lines = append(p.Lines, line)
if len(p.Lines) > 8 {
p.Lines = p.Lines[len(p.Lines)-8:]
}
}

func (p *AgentPanel) Render(width int) string {
p.mu.Lock()
defer p.mu.Unlock()
statusColor := "#777777"
statusIcon := "?"
switch p.Status {
case AgentRunning:
statusColor = "#00FFFF"
statusIcon = ">"
case AgentDone:
statusColor = "#00FF00"
statusIcon = "v"
case AgentFailed:
statusColor = "#FF4444"
statusIcon = "x"
case AgentSkipped:
statusColor = "#555555"
statusIcon = "-"
}
s := lipgloss.NewStyle()
header := s.Bold(true).Foreground(lipgloss.Color(statusColor)).Render(
fmt.Sprintf("%s [%s] %s", statusIcon, p.AgentID, p.Name))
var sb strings.Builder
sb.WriteString(header + "\n")
if p.Findings > 0 {
sb.WriteString(s.Foreground(lipgloss.Color("#FF6600")).Render(
fmt.Sprintf("  %d findings", p.Findings)) + "\n")
}
for _, line := range p.Lines {
trimmed := line
if len(trimmed) > width-4 {
trimmed = trimmed[:width-4] + "..."
}
sb.WriteString(s.Foreground(lipgloss.Color("#888888")).Render("  "+trimmed) + "\n")
}
return sb.String()
}

func SelectAgentsForMode(mode, plan string, mem *TargetMemory) []Agent {
all := All16Agents()
switch mode {
case "quick":
var sel []Agent
for _, a := range all {
if a.Phase == 1 || a.Role == AgentNuclei || a.Role == AgentXSS {
sel = append(sel, a)
}
}
return sel
case "deep", "overnight":
return all
case "stealth":
var sel []Agent
for _, a := range all {
if a.Role == AgentRecon || a.Role == AgentSubdomain || a.Role == AgentJSIntel {
sel = append(sel, a)
}
}
return sel
default:
var sel []Agent
for _, a := range all {
if a.Phase <= 2 {
sel = append(sel, a)
}
}
return sel
}
}

func PrintAgentPlan(agents []Agent) {
s := lipgloss.NewStyle()
fmt.Println()
fmt.Println(s.Bold(true).Foreground(lipgloss.Color("#00FFFF")).Render(
fmt.Sprintf("  %d Specialist Agents Selected", len(agents))))
fmt.Println(s.Foreground(lipgloss.Color("#333333")).Render("  " + strings.Repeat("-", 60)))
phaseNames := map[int]string{1: "RECON", 2: "HUNT", 3: "EXPLOIT"}
currentPhase := 0
for _, a := range agents {
if a.Phase != currentPhase {
currentPhase = a.Phase
fmt.Println(s.Bold(true).Foreground(lipgloss.Color("#FFD700")).Render(
fmt.Sprintf("\n  Phase %d -- %s", a.Phase, phaseNames[a.Phase])))
}
fmt.Println(s.Foreground(lipgloss.Color("#E0E0E0")).Render(
fmt.Sprintf("    [%s] %s", a.Role, a.Name)))
fmt.Println(s.Foreground(lipgloss.Color("#555555")).Render(
fmt.Sprintf("      Tools: %s", strings.Join(a.Tools, ", "))))
}
fmt.Println()
}

func RunAgents(target string, agents []Agent, mem *TargetMemory, onUpdate func([]*AgentPanel)) []AgentResult {
panels := make([]*AgentPanel, len(agents))
for i, a := range agents {
panels[i] = &AgentPanel{AgentID: a.Role, Name: a.Name, Status: AgentPending}
}
results := make([]AgentResult, len(agents))
phases := []int{1, 2, 3}
for _, phase := range phases {
var phaseWg sync.WaitGroup
for i, a := range agents {
if a.Phase != phase {
continue
}
i, a := i, a
phaseWg.Add(1)
go func() {
defer phaseWg.Done()
panels[i].Status = AgentRunning
if onUpdate != nil {
onUpdate(panels)
}
start := time.Now()
output, findings := runAgent(a, target, mem, func(line string) {
panels[i].AddLine(line)
if onUpdate != nil {
onUpdate(panels)
}
})
for _, bug := range findings {
RecordBug(target, bug)
RecordTargetVuln(target, bug.Type, bug.Severity, bug.URL, bug.Tool)
}
results[i] = AgentResult{
AgentID:  a.Role,
Name:     a.Name,
Status:   AgentDone,
Output:   output,
Findings: findings,
Duration: time.Since(start),
}
panels[i].Status = AgentDone
panels[i].Findings = len(findings)
if onUpdate != nil {
onUpdate(panels)
}
}()
}
phaseWg.Wait()
}
return results
}

func GetGraphSummary(target string) string {
g := LoadGraph()
targetID := "target:" + target
vulnCount := 0
for _, edge := range g.Edges {
if edge.From == targetID && edge.Type == EdgeHasVuln {
vulnCount++
}
}
if vulnCount == 0 && len(g.Nodes) == 0 {
return "  Knowledge Graph: empty (first run)"
}
return fmt.Sprintf("  Knowledge Graph: %d nodes | %d vulns for %s | %d edges",
len(g.Nodes), vulnCount, target, len(g.Edges))
}

func RecordTargetInGraph(target string, mem *TargetMemory) {
RecordTargetTech(target, mem.TechStack)
for _, bug := range mem.BugsFound {
RecordTargetVuln(target, bug.Type, bug.Severity, bug.URL, bug.Tool)
}
if mem.WAFDetected && mem.WAFVendor != "" {
for _, pattern := range mem.PatternsWorked {
if strings.Contains(strings.ToLower(pattern.Type), "waf") {
RecordWAFBypass(target, mem.WAFVendor, pattern.Payload, pattern.Type)
}
}
}
}

func GetGraphContext(target string) string {
g := LoadGraph()
mem := LoadTarget(target)
var sb strings.Builder
sb.WriteString("KNOWLEDGE GRAPH CONTEXT:\n")
relatedVulns := GetRelatedVulns(target, mem.TechStack)
if len(relatedVulns) > 0 {
sb.WriteString(fmt.Sprintf("Similar targets had: %s\n", strings.Join(relatedVulns, ", ")))
}
suggestions := GetAttackPathSuggestions(target, mem.TechStack)
for _, s := range suggestions {
sb.WriteString("- " + s + "\n")
}
if mem.WAFDetected {
bypass := GetBestWAFBypass(mem.WAFVendor)
if bypass != "" {
sb.WriteString(fmt.Sprintf("WAF bypass for %s: %s\n", mem.WAFVendor, bypass))
}
}
sb.WriteString(fmt.Sprintf("Graph: %d nodes, %d edges\n", len(g.Nodes), len(g.Edges)))
return sb.String()
}
