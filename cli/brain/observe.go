// observe.go — CyberMind Self-Observation Engine
// The agent watches itself, learns from every scan, and continuously improves.
// Implements: self-monitoring, adaptive strategy, confidence calibration,
// tool performance tracking, and autonomous decision refinement.
package brain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── Observation Types ────────────────────────────────────────────────────────

// ToolObservation records what happened when a tool ran.
type ToolObservation struct {
	Tool        string        `json:"tool"`
	Target      string        `json:"target"`
	Duration    time.Duration `json:"duration_ms"`
	Success     bool          `json:"success"`
	FindingsN   int           `json:"findings_n"`
	ErrorMsg    string        `json:"error_msg,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
	VulnTypes   []string      `json:"vuln_types,omitempty"`
}

// ScanObservation records a full scan session.
type ScanObservation struct {
	SessionID   string            `json:"session_id"`
	Target      string            `json:"target"`
	Mode        string            `json:"mode"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time"`
	Tools       []ToolObservation `json:"tools"`
	BugsFound   int               `json:"bugs_found"`
	BugTypes    []string          `json:"bug_types"`
	TechStack   []string          `json:"tech_stack"`
	WAFDetected bool              `json:"waf_detected"`
	WAFVendor   string            `json:"waf_vendor"`
	Decision    string            `json:"decision"` // what the agent decided to do next
	Outcome     string            `json:"outcome"`  // success/fail/partial
}

// ToolStats aggregates performance stats for a tool across all scans.
type ToolStats struct {
	Tool          string    `json:"tool"`
	TotalRuns     int       `json:"total_runs"`
	SuccessRuns   int       `json:"success_runs"`
	TotalFindings int       `json:"total_findings"`
	AvgDurationMs int64     `json:"avg_duration_ms"`
	LastUsed      time.Time `json:"last_used"`
	BestVulnTypes []string  `json:"best_vuln_types"`
}

// AgentSelfModel is the agent's model of itself — what it's good at, what it's learned.
type AgentSelfModel struct {
	TotalScans       int                  `json:"total_scans"`
	TotalBugsFound   int                  `json:"total_bugs_found"`
	BestTools        []string             `json:"best_tools"`        // tools with highest finding rate
	WeakTools        []string             `json:"weak_tools"`        // tools that rarely find anything
	BestVulnTypes    []string             `json:"best_vuln_types"`   // vuln types found most often
	BestTechTargets  []string             `json:"best_tech_targets"` // tech stacks where bugs found
	AvgBugsPerScan   float64              `json:"avg_bugs_per_scan"`
	SuccessRate      float64              `json:"success_rate"`      // % scans that found bugs
	ToolStats        map[string]ToolStats `json:"tool_stats"`
	LastUpdated      time.Time            `json:"last_updated"`
	Observations     []ScanObservation    `json:"observations"`      // last 50 scans
}

// ─── Storage ──────────────────────────────────────────────────────────────────

func selfModelPath() string {
	return filepath.Join(brainDir(), "self_model.json")
}

// LoadSelfModel loads the agent's self-model from disk.
func LoadSelfModel() AgentSelfModel {
	data, err := os.ReadFile(selfModelPath())
	if err != nil {
		return AgentSelfModel{
			ToolStats:    make(map[string]ToolStats),
			Observations: []ScanObservation{},
		}
	}
	var m AgentSelfModel
	if err := json.Unmarshal(data, &m); err != nil {
		return AgentSelfModel{
			ToolStats:    make(map[string]ToolStats),
			Observations: []ScanObservation{},
		}
	}
	if m.ToolStats == nil {
		m.ToolStats = make(map[string]ToolStats)
	}
	return m
}

// SaveSelfModel saves the agent's self-model to disk.
func SaveSelfModel(m AgentSelfModel) {
	m.LastUpdated = time.Now()
	// Keep only last 50 observations to avoid unbounded growth
	if len(m.Observations) > 50 {
		m.Observations = m.Observations[len(m.Observations)-50:]
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(brainDir(), 0700)
	os.WriteFile(selfModelPath(), data, 0600)
}

// ─── Observation Recording ────────────────────────────────────────────────────

// RecordToolRun records the result of running a tool.
func RecordToolRun(target, tool string, duration time.Duration, success bool, findingsN int, vulnTypes []string, errMsg string) {
	m := LoadSelfModel()

	obs := ToolObservation{
		Tool:      tool,
		Target:    target,
		Duration:  duration,
		Success:   success,
		FindingsN: findingsN,
		VulnTypes: vulnTypes,
		ErrorMsg:  errMsg,
		Timestamp: time.Now(),
	}

	// Update tool stats
	stats := m.ToolStats[tool]
	stats.Tool = tool
	stats.TotalRuns++
	if success {
		stats.SuccessRuns++
	}
	stats.TotalFindings += findingsN
	// Running average of duration
	if stats.TotalRuns > 1 {
		stats.AvgDurationMs = (stats.AvgDurationMs*int64(stats.TotalRuns-1) + duration.Milliseconds()) / int64(stats.TotalRuns)
	} else {
		stats.AvgDurationMs = duration.Milliseconds()
	}
	stats.LastUsed = time.Now()
	// Track which vuln types this tool finds
	for _, vt := range vulnTypes {
		if !containsStr(stats.BestVulnTypes, vt) {
			stats.BestVulnTypes = append(stats.BestVulnTypes, vt)
		}
	}
	m.ToolStats[tool] = stats
	_ = obs // stored in scan observation

	SaveSelfModel(m)
}

// RecordScanComplete records a completed scan session and updates the self-model.
func RecordScanComplete(obs ScanObservation) {
	m := LoadSelfModel()

	m.TotalScans++
	m.TotalBugsFound += obs.BugsFound
	if obs.BugsFound > 0 {
		// Update best vuln types
		for _, bt := range obs.BugTypes {
			if !containsStr(m.BestVulnTypes, bt) {
				m.BestVulnTypes = append(m.BestVulnTypes, bt)
			}
		}
		// Update best tech targets
		for _, tech := range obs.TechStack {
			if !containsStr(m.BestTechTargets, tech) {
				m.BestTechTargets = append(m.BestTechTargets, tech)
			}
		}
	}

	// Recalculate averages
	if m.TotalScans > 0 {
		m.AvgBugsPerScan = float64(m.TotalBugsFound) / float64(m.TotalScans)
	}

	// Count successful scans (found at least 1 bug)
	successCount := 0
	for _, o := range m.Observations {
		if o.BugsFound > 0 {
			successCount++
		}
	}
	if obs.BugsFound > 0 {
		successCount++
	}
	if m.TotalScans > 0 {
		m.SuccessRate = float64(successCount) / float64(m.TotalScans)
	}

	// Update best/weak tools
	m.BestTools = getBestTools(m.ToolStats, 5)
	m.WeakTools = getWeakTools(m.ToolStats, 3)

	// Add observation
	m.Observations = append(m.Observations, obs)

	SaveSelfModel(m)
}

// ─── Self-Reflection ──────────────────────────────────────────────────────────

// SelfReflect generates insights about the agent's performance and suggests improvements.
func SelfReflect() string {
	m := LoadSelfModel()
	if m.TotalScans == 0 {
		return "No scan history yet. Run your first scan to start learning."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  🧠 SELF-REFLECTION — %d scans analyzed\n", m.TotalScans))
	sb.WriteString(fmt.Sprintf("  Success rate: %.0f%% | Avg bugs/scan: %.1f\n\n", m.SuccessRate*100, m.AvgBugsPerScan))

	if len(m.BestTools) > 0 {
		sb.WriteString(fmt.Sprintf("  Best tools: %s\n", strings.Join(m.BestTools, " → ")))
	}
	if len(m.WeakTools) > 0 {
		sb.WriteString(fmt.Sprintf("  Underperforming: %s (consider skipping)\n", strings.Join(m.WeakTools, ", ")))
	}
	if len(m.BestVulnTypes) > 0 {
		sb.WriteString(fmt.Sprintf("  Most found vulns: %s\n", strings.Join(m.BestVulnTypes[:min3(len(m.BestVulnTypes), 5)], ", ")))
	}
	if len(m.BestTechTargets) > 0 {
		sb.WriteString(fmt.Sprintf("  Best tech targets: %s\n", strings.Join(m.BestTechTargets[:min3(len(m.BestTechTargets), 3)], ", ")))
	}

	// Adaptive recommendations
	sb.WriteString("\n  Adaptive recommendations:\n")
	if m.SuccessRate < 0.3 {
		sb.WriteString("  → Low success rate — try focusing on specific vuln types with /hunt --focus xss,idor\n")
	}
	if m.AvgBugsPerScan < 1 {
		sb.WriteString("  → Few bugs found — consider targeting WordPress/PHP apps (higher vuln density)\n")
	}
	if len(m.WeakTools) > 0 {
		sb.WriteString(fmt.Sprintf("  → Skip %s on next scan to save time\n", m.WeakTools[0]))
	}

	return sb.String()
}

// GetAdaptiveToolOrder returns tools sorted by their finding rate for a given target profile.
// The agent uses this to run the most effective tools first.
func GetAdaptiveToolOrder(techStack []string, defaultTools []string) []string {
	m := LoadSelfModel()
	if len(m.ToolStats) == 0 {
		return defaultTools
	}

	type toolScore struct {
		tool  string
		score float64
	}

	var scored []toolScore
	for _, tool := range defaultTools {
		stats, ok := m.ToolStats[tool]
		if !ok || stats.TotalRuns == 0 {
			scored = append(scored, toolScore{tool, 0.5}) // neutral score for unknown tools
			continue
		}
		// Score = finding rate * success rate
		findingRate := float64(stats.TotalFindings) / float64(stats.TotalRuns)
		successRate := float64(stats.SuccessRuns) / float64(stats.TotalRuns)
		score := findingRate*0.7 + successRate*0.3

		// Boost tools that find vuln types common in this tech stack
		techStr := strings.ToLower(strings.Join(techStack, " "))
		for _, vt := range stats.BestVulnTypes {
			if strings.Contains(techStr, vt) {
				score += 0.2
			}
		}
		scored = append(scored, toolScore{tool, score})
	}

	// Sort by score descending
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	result := make([]string, len(scored))
	for i, ts := range scored {
		result[i] = ts.tool
	}
	return result
}

// GetConfidenceBoost returns additional confidence based on self-model.
// If we've found bugs in similar targets before, confidence goes up.
func GetConfidenceBoost(techStack []string, vulnType string) float64 {
	m := LoadSelfModel()
	boost := 0.0

	// Check if we've found this vuln type before
	for _, vt := range m.BestVulnTypes {
		if strings.EqualFold(vt, vulnType) {
			boost += 0.1
			break
		}
	}

	// Check if we've found bugs in this tech stack before
	techStr := strings.ToLower(strings.Join(techStack, " "))
	for _, bt := range m.BestTechTargets {
		if strings.Contains(techStr, strings.ToLower(bt)) {
			boost += 0.15
			break
		}
	}

	// High success rate = more confidence
	if m.SuccessRate > 0.5 {
		boost += 0.1
	}

	if boost > 0.4 {
		boost = 0.4 // cap at +40%
	}
	return boost
}

// GetSelfModelContext returns a string context for AI prompts — tells the AI what we've learned.
func GetSelfModelContext() string {
	m := LoadSelfModel()
	if m.TotalScans == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("AGENT SELF-MODEL (learned from %d scans):\n", m.TotalScans))
	sb.WriteString(fmt.Sprintf("- Success rate: %.0f%% | Avg bugs/scan: %.1f\n", m.SuccessRate*100, m.AvgBugsPerScan))

	if len(m.BestTools) > 0 {
		sb.WriteString(fmt.Sprintf("- Best performing tools: %s\n", strings.Join(m.BestTools, ", ")))
	}
	if len(m.BestVulnTypes) > 0 {
		n := len(m.BestVulnTypes)
		if n > 5 {
			n = 5
		}
		sb.WriteString(fmt.Sprintf("- Most found vuln types: %s\n", strings.Join(m.BestVulnTypes[:n], ", ")))
	}
	if len(m.BestTechTargets) > 0 {
		n := len(m.BestTechTargets)
		if n > 3 {
			n = 3
		}
		sb.WriteString(fmt.Sprintf("- Best tech targets: %s\n", strings.Join(m.BestTechTargets[:n], ", ")))
	}

	return sb.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func getBestTools(stats map[string]ToolStats, n int) []string {
	type ts struct {
		tool  string
		score float64
	}
	var scored []ts
	for tool, s := range stats {
		if s.TotalRuns < 2 {
			continue
		}
		score := float64(s.TotalFindings) / float64(s.TotalRuns)
		scored = append(scored, ts{tool, score})
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].score > scored[j].score })
	result := make([]string, 0, n)
	for i, s := range scored {
		if i >= n {
			break
		}
		if s.score > 0 {
			result = append(result, s.tool)
		}
	}
	return result
}

func getWeakTools(stats map[string]ToolStats, n int) []string {
	type ts struct {
		tool  string
		score float64
	}
	var scored []ts
	for tool, s := range stats {
		if s.TotalRuns < 3 { // need at least 3 runs to call it weak
			continue
		}
		score := float64(s.TotalFindings) / float64(s.TotalRuns)
		scored = append(scored, ts{tool, score})
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].score < scored[j].score })
	result := make([]string, 0, n)
	for i, s := range scored {
		if i >= n {
			break
		}
		if s.score == 0 {
			result = append(result, s.tool)
		}
	}
	return result
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}
