// brain/incremental.go — Incremental scan mode + continuous monitoring + diff tracking
// --incremental: only scan new findings since last run
// --monitor: continuous monitoring with configurable interval
// diff mode: highlight new findings vs last scan
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

// ─── Snapshot Types ───────────────────────────────────────────────────────────

// ScanSnapshot captures the state of a target at a point in time.
// Used for diff tracking — compare current vs previous scan.
type ScanSnapshot struct {
	Target      string    `json:"target"`
	Timestamp   time.Time `json:"timestamp"`
	RunID       string    `json:"run_id"`
	Mode        string    `json:"mode"` // recon, hunt, full

	// Discovered assets
	Subdomains  []string `json:"subdomains"`
	LiveURLs    []string `json:"live_urls"`
	OpenPorts   []int    `json:"open_ports"`
	Technologies []string `json:"technologies"`

	// Vulnerabilities
	Vulns       []SnapshotVuln `json:"vulns"`
	JSSecrets   []string       `json:"js_secrets"`
	CloudBuckets []string      `json:"cloud_buckets"`
	TakeoverCandidates []string `json:"takeover_candidates"`

	// Metadata
	SubdomainCount int `json:"subdomain_count"`
	VulnCount      int `json:"vuln_count"`
	NewAssets      int `json:"new_assets"` // vs previous snapshot
}

// SnapshotVuln is a lightweight vuln record for snapshot comparison.
type SnapshotVuln struct {
	Type     string `json:"type"`
	URL      string `json:"url"`
	Severity string `json:"severity"`
	Tool     string `json:"tool"`
	Evidence string `json:"evidence"`
}

// ScanDiff represents what changed between two snapshots.
type ScanDiff struct {
	Target      string    `json:"target"`
	PrevRun     time.Time `json:"prev_run"`
	CurrentRun  time.Time `json:"current_run"`

	// New findings (not in previous snapshot)
	NewSubdomains  []string       `json:"new_subdomains"`
	NewURLs        []string       `json:"new_urls"`
	NewPorts       []int          `json:"new_ports"`
	NewVulns       []SnapshotVuln `json:"new_vulns"`
	NewSecrets     []string       `json:"new_secrets"`
	NewBuckets     []string       `json:"new_buckets"`
	NewTakeovers   []string       `json:"new_takeovers"`

	// Removed findings (in previous but not current)
	RemovedSubdomains []string `json:"removed_subdomains"`
	RemovedURLs       []string `json:"removed_urls"`
	RemovedPorts      []int    `json:"removed_ports"`

	// Summary
	TotalNew     int  `json:"total_new"`
	TotalRemoved int  `json:"total_removed"`
	HasCritical  bool `json:"has_critical"`
}

// MonitorConfig holds continuous monitoring settings.
type MonitorConfig struct {
	Target          string        `json:"target"`
	Interval        time.Duration `json:"interval"`         // scan interval
	MaxCycles       int           `json:"max_cycles"`       // 0 = infinite
	Mode            string        `json:"mode"`             // recon, hunt, full
	NotifyOnNew     bool          `json:"notify_on_new"`    // notify on new findings
	NotifyOnCritical bool         `json:"notify_on_critical"` // notify on critical vulns
	OutputDir       string        `json:"output_dir"`
}

// ─── Storage ──────────────────────────────────────────────────────────────────

func snapshotDir(target string) string {
	safe := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), "/", "_")
	return filepath.Join(brainDir(), "snapshots", safe)
}

func snapshotFile(target, runID string) string {
	return filepath.Join(snapshotDir(target), runID+".json")
}

// SaveSnapshot saves a scan snapshot to disk.
func SaveSnapshot(snap ScanSnapshot) error {
	dir := snapshotDir(snap.Target)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(snapshotFile(snap.Target, snap.RunID), data, 0644)
}

// LoadLatestSnapshot loads the most recent snapshot for a target.
func LoadLatestSnapshot(target string) (*ScanSnapshot, error) {
	dir := snapshotDir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("no snapshots found for %s", target)
	}

	// Sort by name (timestamp-based run IDs sort chronologically)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name() // descending
	})

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var snap ScanSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		return &snap, nil
	}
	return nil, fmt.Errorf("no valid snapshots found for %s", target)
}

// LoadAllSnapshots loads all snapshots for a target (for trend analysis).
func LoadAllSnapshots(target string) []ScanSnapshot {
	dir := snapshotDir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var snaps []ScanSnapshot
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var snap ScanSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		snaps = append(snaps, snap)
	}
	// Sort by timestamp ascending
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].Timestamp.Before(snaps[j].Timestamp)
	})
	return snaps
}

// ─── Diff Engine ──────────────────────────────────────────────────────────────

// DiffSnapshots compares two snapshots and returns what changed.
func DiffSnapshots(prev, current *ScanSnapshot) ScanDiff {
	diff := ScanDiff{
		Target:     current.Target,
		PrevRun:    prev.Timestamp,
		CurrentRun: current.Timestamp,
	}

	// New subdomains
	prevSubs := toSet(prev.Subdomains)
	for _, s := range current.Subdomains {
		if !prevSubs[s] {
			diff.NewSubdomains = append(diff.NewSubdomains, s)
		}
	}

	// Removed subdomains
	currSubs := toSet(current.Subdomains)
	for _, s := range prev.Subdomains {
		if !currSubs[s] {
			diff.RemovedSubdomains = append(diff.RemovedSubdomains, s)
		}
	}

	// New URLs
	prevURLs := toSet(prev.LiveURLs)
	for _, u := range current.LiveURLs {
		if !prevURLs[u] {
			diff.NewURLs = append(diff.NewURLs, u)
		}
	}

	// Removed URLs
	currURLs := toSet(current.LiveURLs)
	for _, u := range prev.LiveURLs {
		if !currURLs[u] {
			diff.RemovedURLs = append(diff.RemovedURLs, u)
		}
	}

	// New ports
	prevPorts := toIntSet(prev.OpenPorts)
	for _, p := range current.OpenPorts {
		if !prevPorts[p] {
			diff.NewPorts = append(diff.NewPorts, p)
		}
	}

	// Removed ports
	currPorts := toIntSet(current.OpenPorts)
	for _, p := range prev.OpenPorts {
		if !currPorts[p] {
			diff.RemovedPorts = append(diff.RemovedPorts, p)
		}
	}

	// New vulns (by URL+type key)
	prevVulnKeys := map[string]bool{}
	for _, v := range prev.Vulns {
		prevVulnKeys[v.URL+"|"+v.Type] = true
	}
	for _, v := range current.Vulns {
		if !prevVulnKeys[v.URL+"|"+v.Type] {
			diff.NewVulns = append(diff.NewVulns, v)
			if v.Severity == "critical" || v.Severity == "high" {
				diff.HasCritical = true
			}
		}
	}

	// New secrets
	prevSecrets := toSet(prev.JSSecrets)
	for _, s := range current.JSSecrets {
		if !prevSecrets[s] {
			diff.NewSecrets = append(diff.NewSecrets, s)
		}
	}

	// New cloud buckets
	prevBuckets := toSet(prev.CloudBuckets)
	for _, b := range current.CloudBuckets {
		if !prevBuckets[b] {
			diff.NewBuckets = append(diff.NewBuckets, b)
		}
	}

	// New takeover candidates
	prevTakeovers := toSet(prev.TakeoverCandidates)
	for _, t := range current.TakeoverCandidates {
		if !prevTakeovers[t] {
			diff.NewTakeovers = append(diff.NewTakeovers, t)
			diff.HasCritical = true // takeovers are always critical
		}
	}

	diff.TotalNew = len(diff.NewSubdomains) + len(diff.NewURLs) + len(diff.NewVulns) +
		len(diff.NewSecrets) + len(diff.NewBuckets) + len(diff.NewTakeovers)
	diff.TotalRemoved = len(diff.RemovedSubdomains) + len(diff.RemovedURLs) + len(diff.RemovedPorts)

	return diff
}

// FormatDiff returns a human-readable diff summary.
func FormatDiff(diff ScanDiff) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n  📊 DIFF REPORT — %s\n", diff.Target))
	sb.WriteString(fmt.Sprintf("  Previous scan: %s\n", diff.PrevRun.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Current scan:  %s\n\n", diff.CurrentRun.Format("2006-01-02 15:04:05")))

	if diff.TotalNew == 0 && diff.TotalRemoved == 0 {
		sb.WriteString("  ✓ No changes detected since last scan\n")
		return sb.String()
	}

	if diff.HasCritical {
		sb.WriteString("  🚨 CRITICAL NEW FINDINGS DETECTED!\n\n")
	}

	if len(diff.NewSubdomains) > 0 {
		sb.WriteString(fmt.Sprintf("  🌐 NEW SUBDOMAINS (%d):\n", len(diff.NewSubdomains)))
		for _, s := range diff.NewSubdomains {
			sb.WriteString(fmt.Sprintf("     + %s\n", s))
		}
		sb.WriteString("\n")
	}

	if len(diff.NewVulns) > 0 {
		sb.WriteString(fmt.Sprintf("  🐛 NEW VULNERABILITIES (%d):\n", len(diff.NewVulns)))
		for _, v := range diff.NewVulns {
			sb.WriteString(fmt.Sprintf("     [%s] %s — %s\n",
				strings.ToUpper(v.Severity), v.Type, v.URL))
		}
		sb.WriteString("\n")
	}

	if len(diff.NewTakeovers) > 0 {
		sb.WriteString(fmt.Sprintf("  ⚠️  NEW TAKEOVER CANDIDATES (%d):\n", len(diff.NewTakeovers)))
		for _, t := range diff.NewTakeovers {
			sb.WriteString(fmt.Sprintf("     ⚠️  %s\n", t))
		}
		sb.WriteString("\n")
	}

	if len(diff.NewSecrets) > 0 {
		sb.WriteString(fmt.Sprintf("  🔑 NEW SECRETS/API KEYS (%d):\n", len(diff.NewSecrets)))
		for _, s := range diff.NewSecrets {
			if len(s) > 80 {
				s = s[:80] + "..."
			}
			sb.WriteString(fmt.Sprintf("     🔑 %s\n", s))
		}
		sb.WriteString("\n")
	}

	if len(diff.NewURLs) > 0 {
		sb.WriteString(fmt.Sprintf("  🔗 NEW LIVE URLS (%d):\n", len(diff.NewURLs)))
		for i, u := range diff.NewURLs {
			if i >= 10 {
				sb.WriteString(fmt.Sprintf("     ... and %d more\n", len(diff.NewURLs)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("     + %s\n", u))
		}
		sb.WriteString("\n")
	}

	if len(diff.NewPorts) > 0 {
		sb.WriteString(fmt.Sprintf("  🔌 NEW OPEN PORTS (%d): %v\n\n", len(diff.NewPorts), diff.NewPorts))
	}

	if len(diff.RemovedSubdomains) > 0 {
		sb.WriteString(fmt.Sprintf("  ➖ REMOVED SUBDOMAINS (%d):\n", len(diff.RemovedSubdomains)))
		for _, s := range diff.RemovedSubdomains {
			sb.WriteString(fmt.Sprintf("     - %s\n", s))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("  Summary: +%d new, -%d removed\n", diff.TotalNew, diff.TotalRemoved))
	return sb.String()
}

// ─── Incremental Mode ─────────────────────────────────────────────────────────

// IncrementalFilter returns only new subdomains/URLs not seen in previous snapshot.
// Used by --incremental flag to skip already-tested assets.
type IncrementalFilter struct {
	KnownSubdomains map[string]bool
	KnownURLs       map[string]bool
	KnownPorts      map[int]bool
	HasPrevious     bool
}

// NewIncrementalFilter creates a filter from the latest snapshot.
func NewIncrementalFilter(target string) *IncrementalFilter {
	filter := &IncrementalFilter{
		KnownSubdomains: map[string]bool{},
		KnownURLs:       map[string]bool{},
		KnownPorts:      map[int]bool{},
	}

	snap, err := LoadLatestSnapshot(target)
	if err != nil {
		return filter // no previous snapshot — scan everything
	}

	filter.HasPrevious = true
	for _, s := range snap.Subdomains {
		filter.KnownSubdomains[s] = true
	}
	for _, u := range snap.LiveURLs {
		filter.KnownURLs[u] = true
	}
	for _, p := range snap.OpenPorts {
		filter.KnownPorts[p] = true
	}
	return filter
}

// IsNewSubdomain returns true if subdomain was not seen in previous scan.
func (f *IncrementalFilter) IsNewSubdomain(sub string) bool {
	if !f.HasPrevious {
		return true
	}
	return !f.KnownSubdomains[sub]
}

// FilterNewSubdomains returns only subdomains not seen before.
func (f *IncrementalFilter) FilterNewSubdomains(subs []string) []string {
	if !f.HasPrevious {
		return subs
	}
	var newSubs []string
	for _, s := range subs {
		if !f.KnownSubdomains[s] {
			newSubs = append(newSubs, s)
		}
	}
	return newSubs
}

// FilterNewURLs returns only URLs not seen before.
func (f *IncrementalFilter) FilterNewURLs(urls []string) []string {
	if !f.HasPrevious {
		return urls
	}
	var newURLs []string
	for _, u := range urls {
		if !f.KnownURLs[u] {
			newURLs = append(newURLs, u)
		}
	}
	return newURLs
}

// ─── Monitor Mode ─────────────────────────────────────────────────────────────

// MonitorSession tracks a continuous monitoring session.
type MonitorSession struct {
	Config    MonitorConfig
	StartTime time.Time
	Cycles    int
	Diffs     []ScanDiff
	Running   bool
}

// NewMonitorSession creates a new monitoring session.
func NewMonitorSession(cfg MonitorConfig) *MonitorSession {
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Minute // default: 1 hour
	}
	if cfg.OutputDir == "" {
		home, _ := os.UserHomeDir()
		cfg.OutputDir = filepath.Join(home, ".cybermind", "monitor", cfg.Target)
	}
	os.MkdirAll(cfg.OutputDir, 0755)
	return &MonitorSession{
		Config:    cfg,
		StartTime: time.Now(),
		Running:   true,
	}
}

// ShouldContinue returns true if monitoring should continue.
func (m *MonitorSession) ShouldContinue() bool {
	if !m.Running {
		return false
	}
	if m.Config.MaxCycles > 0 && m.Cycles >= m.Config.MaxCycles {
		return false
	}
	return true
}

// RecordDiff records a diff from a monitoring cycle.
func (m *MonitorSession) RecordDiff(diff ScanDiff) {
	m.Diffs = append(m.Diffs, diff)
	m.Cycles++

	// Save diff to output dir
	diffFile := filepath.Join(m.Config.OutputDir,
		fmt.Sprintf("diff_%s.json", time.Now().Format("2006-01-02_15-04-05")))
	data, _ := json.MarshalIndent(diff, "", "  ")
	os.WriteFile(diffFile, data, 0644)
}

// MonitorSummary returns a summary of all monitoring cycles.
func (m *MonitorSession) MonitorSummary() string {
	var sb strings.Builder
	elapsed := time.Since(m.StartTime).Round(time.Minute)

	sb.WriteString(fmt.Sprintf("\n  📡 MONITOR SUMMARY — %s\n", m.Config.Target))
	sb.WriteString(fmt.Sprintf("  Duration: %s | Cycles: %d\n\n", elapsed, m.Cycles))

	totalNew := 0
	criticalFound := false
	for _, d := range m.Diffs {
		totalNew += d.TotalNew
		if d.HasCritical {
			criticalFound = true
		}
	}

	sb.WriteString(fmt.Sprintf("  Total new findings across all cycles: %d\n", totalNew))
	if criticalFound {
		sb.WriteString("  🚨 Critical findings detected during monitoring!\n")
	}
	sb.WriteString(fmt.Sprintf("  Diffs saved to: %s\n", m.Config.OutputDir))
	return sb.String()
}

// ─── Hotlist Builder ──────────────────────────────────────────────────────────

// HotlistEntry represents a high-risk asset worth immediate attention.
type HotlistEntry struct {
	Asset    string  `json:"asset"`
	Type     string  `json:"type"`     // subdomain, url, vuln, secret, takeover
	Score    float64 `json:"score"`    // 0-100 risk score
	Reason   string  `json:"reason"`
	Severity string  `json:"severity"`
}

// BuildHotlist scores and ranks assets by risk for immediate attention.
// Returns top N highest-risk assets.
func BuildHotlist(snap *ScanSnapshot, diff *ScanDiff, limit int) []HotlistEntry {
	var entries []HotlistEntry

	// Takeover candidates — always critical (score 100)
	for _, t := range snap.TakeoverCandidates {
		entries = append(entries, HotlistEntry{
			Asset:    t,
			Type:     "takeover",
			Score:    100,
			Reason:   "Subdomain takeover candidate — immediate action required",
			Severity: "critical",
		})
	}

	// New vulns from diff — score by severity
	if diff != nil {
		for _, v := range diff.NewVulns {
			score := 50.0
			switch v.Severity {
			case "critical":
				score = 95
			case "high":
				score = 80
			case "medium":
				score = 60
			case "low":
				score = 40
			}
			entries = append(entries, HotlistEntry{
				Asset:    v.URL,
				Type:     "vuln",
				Score:    score,
				Reason:   fmt.Sprintf("NEW %s vulnerability: %s", strings.ToUpper(v.Severity), v.Type),
				Severity: v.Severity,
			})
		}

		// New secrets — high risk
		for _, s := range diff.NewSecrets {
			entries = append(entries, HotlistEntry{
				Asset:    s,
				Type:     "secret",
				Score:    85,
				Reason:   "NEW exposed secret/API key detected",
				Severity: "high",
			})
		}

		// New subdomains — medium risk (new attack surface)
		for _, sub := range diff.NewSubdomains {
			entries = append(entries, HotlistEntry{
				Asset:    sub,
				Type:     "subdomain",
				Score:    45,
				Reason:   "NEW subdomain discovered — unexplored attack surface",
				Severity: "info",
			})
		}
	}

	// Existing vulns from snapshot
	for _, v := range snap.Vulns {
		score := 50.0
		switch v.Severity {
		case "critical":
			score = 90
		case "high":
			score = 75
		case "medium":
			score = 55
		}
		if score >= 55 {
			entries = append(entries, HotlistEntry{
				Asset:    v.URL,
				Type:     "vuln",
				Score:    score,
				Reason:   fmt.Sprintf("%s vulnerability: %s", strings.ToUpper(v.Severity), v.Type),
				Severity: v.Severity,
			})
		}
	}

	// Sort by score descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})

	// Deduplicate by asset
	seen := map[string]bool{}
	var deduped []HotlistEntry
	for _, e := range entries {
		if !seen[e.Asset] {
			seen[e.Asset] = true
			deduped = append(deduped, e)
		}
	}

	if limit > 0 && len(deduped) > limit {
		return deduped[:limit]
	}
	return deduped
}

// SaveHotlist saves the hotlist to a file.
func SaveHotlist(target string, entries []HotlistEntry) string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind", "recon", strings.ReplaceAll(target, ".", "_"))
	os.MkdirAll(dir, 0755)
	hotlistFile := filepath.Join(dir, "hotlist.txt")

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# CyberMind Hotlist — %s\n", target))
	sb.WriteString(fmt.Sprintf("# Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	for i, e := range entries {
		sb.WriteString(fmt.Sprintf("[%d] Score: %.0f | Type: %s | Severity: %s\n",
			i+1, e.Score, e.Type, e.Severity))
		sb.WriteString(fmt.Sprintf("    Asset:  %s\n", e.Asset))
		sb.WriteString(fmt.Sprintf("    Reason: %s\n\n", e.Reason))
	}

	os.WriteFile(hotlistFile, []byte(sb.String()), 0644)
	return hotlistFile
}

// ─── Asset Store ──────────────────────────────────────────────────────────────

// AssetRecord is a single asset entry in the JSONL asset store.
type AssetRecord struct {
	Target    string    `json:"target"`
	Type      string    `json:"type"`     // subdomain, url, port, vuln, secret
	Value     string    `json:"value"`
	Severity  string    `json:"severity,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	RunID     string    `json:"run_id"`
}

// AppendAssetStore appends findings to the JSONL asset store for automation.
func AppendAssetStore(target string, records []AssetRecord) error {
	home, _ := os.UserHomeDir()
	storeFile := filepath.Join(home, ".cybermind", "assets.jsonl")

	f, err := os.OpenFile(storeFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, r := range records {
		data, err := json.Marshal(r)
		if err != nil {
			continue
		}
		f.WriteString(string(data) + "\n")
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func toSet(items []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		m[s] = true
	}
	return m
}

func toIntSet(items []int) map[int]bool {
	m := map[int]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

// GenerateRunID creates a unique run ID based on timestamp.
func GenerateRunID() string {
	return time.Now().Format("20060102_150405")
}
