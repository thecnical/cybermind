// Package brain — CVSS + EPSS scoring integration.
// Every finding gets CVSS v3.1 base score + EPSS (Exploit Prediction Scoring System) probability.
// EPSS API: https://api.first.org/data/v1/epss
// CVSS: from NVD API (already in cve_feed.go)
package brain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EPSSEntry holds EPSS data for a single CVE.
type EPSSEntry struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`       // 0.0–1.0 probability of exploitation in 30 days
	Percentile float64 `json:"percentile"` // percentile rank among all CVEs
	Date       string  `json:"date"`
}

// ScoredFinding combines a vulnerability finding with CVSS + EPSS scores.
type ScoredFinding struct {
	// Original finding fields
	Title    string
	URL      string
	Tool     string
	Evidence string
	CVE      string

	// Scoring
	CVSSScore   float64 // 0.0–10.0
	CVSSSeverity string  // CRITICAL, HIGH, MEDIUM, LOW
	EPSSScore   float64 // 0.0–1.0 (probability of exploitation in 30 days)
	EPSSPercent float64 // percentile rank
	RiskScore   float64 // combined: EPSS × CVSS (0–10)
	Priority    string  // RED (EPSS>0.5), YELLOW (0.1–0.5), GREEN (<0.1)
}

// EPSSResponse is the API response from api.first.org/data/v1/epss
type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Version    string      `json:"version"`
	Access     string      `json:"access"`
	Total      int         `json:"total"`
	Offset     int         `json:"offset"`
	Limit      int         `json:"limit"`
	Data       []EPSSEntry `json:"data"`
}

// FetchEPSS fetches EPSS scores for a list of CVE IDs from api.first.org.
// Returns a map of CVE ID → EPSSEntry.
// Batches up to 100 CVEs per request.
func FetchEPSS(cveIDs []string) map[string]EPSSEntry {
	result := make(map[string]EPSSEntry)
	if len(cveIDs) == 0 {
		return result
	}

	// Deduplicate and filter valid CVE IDs
	seen := map[string]bool{}
	var valid []string
	for _, id := range cveIDs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return result
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Batch in groups of 100
	batchSize := 100
	for i := 0; i < len(valid); i += batchSize {
		end := i + batchSize
		if end > len(valid) {
			end = len(valid)
		}
		batch := valid[i:end]

		url := "https://api.first.org/data/v1/epss?cve=" + strings.Join(batch, ",")
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		var epssResp EPSSResponse
		if err := json.Unmarshal(body, &epssResp); err != nil {
			continue
		}

		for _, entry := range epssResp.Data {
			result[strings.ToUpper(entry.CVE)] = entry
		}
	}

	return result
}

// ScoreFindings takes a list of CVE entries and enriches them with EPSS scores.
// Returns ScoredFinding list sorted by RiskScore descending (highest priority first).
func ScoreFindings(findings []CVEEntry) []ScoredFinding {
	if len(findings) == 0 {
		return nil
	}

	// Collect CVE IDs for batch EPSS fetch
	var cveIDs []string
	for _, f := range findings {
		if f.ID != "" {
			cveIDs = append(cveIDs, f.ID)
		}
	}

	epssMap := FetchEPSS(cveIDs)

	var scored []ScoredFinding
	for _, f := range findings {
		sf := ScoredFinding{
			Title:        f.ID + " — " + truncateStr(f.Description, 100),
			CVE:          f.ID,
			CVSSScore:    f.CVSS,
			CVSSSeverity: f.Severity,
		}

		// Apply EPSS data
		if epss, ok := epssMap[strings.ToUpper(f.ID)]; ok {
			sf.EPSSScore = epss.EPSS
			sf.EPSSPercent = epss.Percentile
		}

		// Combined risk score: EPSS × CVSS (0–10 scale)
		sf.RiskScore = sf.EPSSScore * sf.CVSSScore

		// Priority color coding
		switch {
		case sf.EPSSScore >= 0.5:
			sf.Priority = "RED"   // 50%+ chance of exploitation in 30 days
		case sf.EPSSScore >= 0.1:
			sf.Priority = "YELLOW" // 10–50% chance
		default:
			sf.Priority = "GREEN"  // <10% chance
		}

		scored = append(scored, sf)
	}

	// Sort by RiskScore descending
	for i := 0; i < len(scored); i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].RiskScore > scored[i].RiskScore {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	return scored
}

// ScoreNucleiFindings scores nuclei output lines that contain CVE IDs.
// Extracts CVE IDs from nuclei output, fetches EPSS, returns scored list.
func ScoreNucleiFindings(nucleiOutput, target string) []ScoredFinding {
	// Extract CVE IDs from nuclei output
	var cveIDs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(nucleiOutput, "\n") {
		// Nuclei format: [cve-2024-1234] [http] [critical] https://...
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "cve-") {
			continue
		}
		// Extract CVE-YYYY-NNNNN pattern
		parts := strings.Fields(line)
		for _, p := range parts {
			p = strings.Trim(p, "[](){}")
			upper := strings.ToUpper(p)
			if strings.HasPrefix(upper, "CVE-") && !seen[upper] {
				seen[upper] = true
				cveIDs = append(cveIDs, upper)
			}
		}
	}

	if len(cveIDs) == 0 {
		return nil
	}

	// Fetch CVSS from NVD for these CVEs
	var cveEntries []CVEEntry
	for _, id := range cveIDs {
		entry, err := FetchCVEByID(id)
		if err != nil || entry == nil {
			// Fallback: create minimal entry
			cveEntries = append(cveEntries, CVEEntry{
				ID:       id,
				CVSS:     0,
				Severity: "UNKNOWN",
			})
			continue
		}
		cveEntries = append(cveEntries, *entry)
	}

	return ScoreFindings(cveEntries)
}

// FormatScoredFindings returns a human-readable report of scored findings.
func FormatScoredFindings(findings []ScoredFinding) string {
	if len(findings) == 0 {
		return "  No CVE findings to score."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  📊 CVSS + EPSS Scoring — %d findings\n", len(findings)))
	sb.WriteString("  " + strings.Repeat("─", 60) + "\n\n")
	sb.WriteString(fmt.Sprintf("  %-20s  %-6s  %-8s  %-8s  %-8s  %s\n",
		"CVE", "CVSS", "EPSS%", "Risk", "Priority", "Severity"))
	sb.WriteString("  " + strings.Repeat("─", 80) + "\n")

	for _, f := range findings {
		priorityIcon := "🟢"
		switch f.Priority {
		case "RED":
			priorityIcon = "🔴"
		case "YELLOW":
			priorityIcon = "🟡"
		}

		sb.WriteString(fmt.Sprintf("  %-20s  %-6.1f  %-8.1f  %-8.2f  %s %-6s  %s\n",
			f.CVE,
			f.CVSSScore,
			f.EPSSScore*100, // show as percentage
			f.RiskScore,
			priorityIcon,
			f.Priority,
			f.CVSSSeverity,
		))
	}

	sb.WriteString("\n")
	sb.WriteString("  EPSS = probability of exploitation in next 30 days (source: api.first.org)\n")
	sb.WriteString("  Risk = EPSS × CVSS — prioritize RED findings first\n")

	// Summary stats
	red, yellow, green := 0, 0, 0
	for _, f := range findings {
		switch f.Priority {
		case "RED":
			red++
		case "YELLOW":
			yellow++
		default:
			green++
		}
	}
	sb.WriteString(fmt.Sprintf("\n  🔴 Critical (EPSS>50%%): %d  🟡 High (10-50%%): %d  🟢 Low (<10%%): %d\n",
		red, yellow, green))

	return sb.String()
}

// GetEPSSForCVE fetches EPSS score for a single CVE ID.
// Returns (epss, percentile, error).
func GetEPSSForCVE(cveID string) (float64, float64, error) {
	m := FetchEPSS([]string{cveID})
	if entry, ok := m[strings.ToUpper(cveID)]; ok {
		return entry.EPSS, entry.Percentile, nil
	}
	return 0, 0, fmt.Errorf("EPSS data not found for %s", cveID)
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
