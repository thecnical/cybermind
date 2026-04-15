// Package brain implements CyberMind's persistent memory and learning system.
// Every run teaches the system â€” patterns that worked, false positives to skip,
// tech stacks, WAF vendors, confirmed bugs, and scope intelligence.
package brain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// â”€â”€â”€ Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// Bug represents a confirmed vulnerability found during a run.
type Bug struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Type        string    `json:"type"`   // xss, sqli, idor, ssrf, rce, etc.
	URL         string    `json:"url"`
	Severity    string    `json:"severity"` // critical, high, medium, low, info
	Evidence    string    `json:"evidence"`
	PoC         string    `json:"poc"`
	CVE         string    `json:"cve,omitempty"`
	Tool        string    `json:"tool"`
	Verified    bool      `json:"verified"`
	Submitted   bool      `json:"submitted"`
	Platform    string    `json:"platform,omitempty"` // hackerone, bugcrowd
	ReportID    string    `json:"report_id,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

// Pattern represents an attack pattern that worked on a target.
type Pattern struct {
	Type        string    `json:"type"`        // "idor_param", "xss_header", etc.
	Description string    `json:"description"`
	Payload     string    `json:"payload,omitempty"`
	Endpoint    string    `json:"endpoint,omitempty"`
	SuccessRate float64   `json:"success_rate"` // 0.0-1.0
	UsedCount   int       `json:"used_count"`
	LastUsed    time.Time `json:"last_used"`
}

// FalsePositive represents a finding that was NOT a real bug.
type FalsePositive struct {
	Tool      string `json:"tool"`
	Type      string `json:"type"`
	Signature string `json:"signature"` // URL pattern or finding signature
	Reason    string `json:"reason"`
}

// TargetMemory holds everything CyberMind has learned about a target.
type TargetMemory struct {
	Target          string          `json:"target"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastTested      time.Time       `json:"last_tested"`
	RunCount        int             `json:"run_count"`
	TechStack       []string        `json:"tech_stack"`
	WAFVendor       string          `json:"waf_vendor"`
	WAFDetected     bool            `json:"waf_detected"`
	SubdomainsFound []string        `json:"subdomains_found"`
	LiveURLs        []string        `json:"live_urls"`
	OpenPorts       []int           `json:"open_ports"`
	BugsFound       []Bug           `json:"bugs_found"`
	PatternsWorked  []Pattern       `json:"patterns_worked"`
	FalsePositives  []FalsePositive `json:"false_positives"`
	TestedEndpoints []string        `json:"tested_endpoints"` // never test twice
	SkipTools       []string        `json:"skip_tools"`       // tools that always fail on this target
	Notes           string          `json:"notes"`
	mu              sync.Mutex      `json:"-"`
}

// GlobalMemory holds cross-target learnings.
type GlobalMemory struct {
	TotalBugsFound    int                `json:"total_bugs_found"`
	TotalTargetsTested int               `json:"total_targets_tested"`
	BestPatterns      []Pattern          `json:"best_patterns"`
	TargetStats       map[string]int     `json:"target_stats"` // target â†’ bug count
	LastUpdated       time.Time          `json:"last_updated"`
}

// â”€â”€â”€ Storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func brainDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cybermind", "brain")
}

func targetFile(target string) string {
	safe := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), "/", "_")
	return filepath.Join(brainDir(), "targets", safe+".json")
}

func globalFile() string {
	return filepath.Join(brainDir(), "global.json")
}

// LoadTarget loads memory for a specific target. Returns empty memory if not found.
func LoadTarget(target string) *TargetMemory {
	mem := &TargetMemory{
		Target:    target,
		FirstSeen: time.Now(),
	}
	data, err := os.ReadFile(targetFile(target))
	if err != nil {
		return mem
	}
	if err := json.Unmarshal(data, mem); err != nil {
		return mem
	}
	return mem
}

// SaveTarget persists target memory to disk.
func SaveTarget(mem *TargetMemory) error {
	mem.mu.Lock()
	defer mem.mu.Unlock()

	dir := filepath.Join(brainDir(), "targets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(mem, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(targetFile(mem.Target), data, 0600)
}

// LoadGlobal loads global cross-target memory.
func LoadGlobal() *GlobalMemory {
	g := &GlobalMemory{
		TargetStats: make(map[string]int),
		LastUpdated: time.Now(),
	}
	data, err := os.ReadFile(globalFile())
	if err != nil {
		return g
	}
	json.Unmarshal(data, g)
	return g
}

// SaveGlobal persists global memory.
func SaveGlobal(g *GlobalMemory) error {
	if err := os.MkdirAll(brainDir(), 0700); err != nil {
		return err
	}
	g.LastUpdated = time.Now()
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(globalFile(), data, 0600)
}

// â”€â”€â”€ Learning API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// RecordRun updates memory after a scan run.
func RecordRun(target string, techStack []string, wafVendor string, wafDetected bool,
	subdomains []string, liveURLs []string, openPorts []int) *TargetMemory {

	mem := LoadTarget(target)
	mem.LastTested = time.Now()
	mem.RunCount++
	mem.WAFVendor = wafVendor
	mem.WAFDetected = wafDetected

	// Merge â€” don't duplicate
	mem.TechStack = mergeUnique(mem.TechStack, techStack)
	mem.SubdomainsFound = mergeUnique(mem.SubdomainsFound, subdomains)
	mem.LiveURLs = mergeUnique(mem.LiveURLs, liveURLs)
	mem.OpenPorts = mergeUniqueInts(mem.OpenPorts, openPorts)

	SaveTarget(mem)
	return mem
}

// RecordBug adds a confirmed bug to memory.
func RecordBug(target string, bug Bug) {
	mem := LoadTarget(target)
	mem.mu.Lock()
	defer mem.mu.Unlock()

	// Don't duplicate
	for _, b := range mem.BugsFound {
		if b.URL == bug.URL && b.Type == bug.Type {
			return
		}
	}
	if bug.ID == "" {
		bug.ID = fmt.Sprintf("%s_%d", bug.Type, time.Now().UnixNano())
	}
	bug.FoundAt = time.Now()
	mem.BugsFound = append(mem.BugsFound, bug)
	SaveTarget(mem)

	// Update global stats
	g := LoadGlobal()
	g.TotalBugsFound++
	g.TargetStats[target]++
	SaveGlobal(g)
}

// RecordPattern records an attack pattern that worked.
func RecordPattern(target, patternType, description, payload, endpoint string) {
	mem := LoadTarget(target)
	mem.mu.Lock()
	defer mem.mu.Unlock()

	// Update existing or add new
	for i, p := range mem.PatternsWorked {
		if p.Type == patternType && p.Endpoint == endpoint {
			mem.PatternsWorked[i].UsedCount++
			mem.PatternsWorked[i].SuccessRate = float64(mem.PatternsWorked[i].UsedCount) / float64(mem.RunCount+1)
			mem.PatternsWorked[i].LastUsed = time.Now()
			SaveTarget(mem)
			return
		}
	}
	mem.PatternsWorked = append(mem.PatternsWorked, Pattern{
		Type:        patternType,
		Description: description,
		Payload:     payload,
		Endpoint:    endpoint,
		SuccessRate: 1.0,
		UsedCount:   1,
		LastUsed:    time.Now(),
	})
	SaveTarget(mem)
}

// RecordFalsePositive marks a finding as a false positive to skip next time.
func RecordFalsePositive(target, tool, findingType, signature, reason string) {
	mem := LoadTarget(target)
	mem.mu.Lock()
	defer mem.mu.Unlock()

	for _, fp := range mem.FalsePositives {
		if fp.Signature == signature {
			return // already recorded
		}
	}
	mem.FalsePositives = append(mem.FalsePositives, FalsePositive{
		Tool:      tool,
		Type:      findingType,
		Signature: signature,
		Reason:    reason,
	})
	SaveTarget(mem)
}

// IsFalsePositive checks if a finding matches a known false positive.
func IsFalsePositive(target, signature string) bool {
	mem := LoadTarget(target)
	for _, fp := range mem.FalsePositives {
		if strings.Contains(signature, fp.Signature) || fp.Signature == signature {
			return true
		}
	}
	return false
}

// IsEndpointTested checks if an endpoint was already tested.
func IsEndpointTested(target, endpoint string) bool {
	mem := LoadTarget(target)
	for _, e := range mem.TestedEndpoints {
		if e == endpoint {
			return true
		}
	}
	return false
}

// MarkEndpointTested records that an endpoint was tested.
func MarkEndpointTested(target, endpoint string) {
	mem := LoadTarget(target)
	mem.mu.Lock()
	defer mem.mu.Unlock()
	if !IsEndpointTested(target, endpoint) {
		mem.TestedEndpoints = append(mem.TestedEndpoints, endpoint)
		SaveTarget(mem)
	}
}

// GetBestPatterns returns patterns sorted by success rate.
func GetBestPatterns(target string) []Pattern {
	mem := LoadTarget(target)
	patterns := mem.PatternsWorked
	// Sort by success rate descending
	for i := 0; i < len(patterns); i++ {
		for j := i + 1; j < len(patterns); j++ {
			if patterns[j].SuccessRate > patterns[i].SuccessRate {
				patterns[i], patterns[j] = patterns[j], patterns[i]
			}
		}
	}
	return patterns
}

// GetMemorySummary returns a human-readable summary of what we know about a target.
func GetMemorySummary(target string) string {
	mem := LoadTarget(target)
	if mem.RunCount == 0 {
		return "  ðŸ§  No prior memory â€” first run on this target"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  ðŸ§  Memory: %d prior runs | %d bugs found | %d subdomains known\n",
		mem.RunCount, len(mem.BugsFound), len(mem.SubdomainsFound)))
	if mem.WAFDetected {
		sb.WriteString(fmt.Sprintf("  ðŸ›¡  WAF: %s (known â€” applying bypass strategy)\n", mem.WAFVendor))
	}
	if len(mem.TechStack) > 0 {
		sb.WriteString(fmt.Sprintf("  âš™ï¸  Tech: %s\n", strings.Join(mem.TechStack[:min(5, len(mem.TechStack))], ", ")))
	}
	if len(mem.PatternsWorked) > 0 {
		sb.WriteString(fmt.Sprintf("  âœ“  %d patterns that worked before â€” applying automatically\n", len(mem.PatternsWorked)))
	}
	if len(mem.FalsePositives) > 0 {
		sb.WriteString(fmt.Sprintf("  âœ—  %d known false positives â€” will skip\n", len(mem.FalsePositives)))
	}
	return sb.String()
}

// â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func mergeUnique(existing, new []string) []string {
	seen := make(map[string]bool)
	for _, s := range existing {
		seen[s] = true
	}
	for _, s := range new {
		if !seen[s] && s != "" {
			seen[s] = true
			existing = append(existing, s)
		}
	}
	return existing
}

func mergeUniqueInts(existing, new []int) []int {
	seen := make(map[int]bool)
	for _, n := range existing {
		seen[n] = true
	}
	for _, n := range new {
		if !seen[n] {
			seen[n] = true
			existing = append(existing, n)
		}
	}
	return existing
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
