package redteam

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/brain"
	"cybermind-cli/storage"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// Campaign holds the full state of a multi-day red team engagement.
type Campaign struct {
	Company   string    `json:"company"`
	Duration  int       `json:"duration"`
	Scope     Scope     `json:"scope"`
	Phases    []Phase   `json:"phases"`
	StartDate time.Time `json:"start_date"`
	StateFile string    `json:"state_file,omitempty"`
}

// Scope defines the authorized target surface for the engagement.
type Scope struct {
	Domains       []string `json:"domains"`
	IPRanges      []string `json:"ip_ranges"`
	AuthConfirmed bool     `json:"auth_confirmed"`
	StartDate     string   `json:"start_date"`
	EndDate       string   `json:"end_date"`
}

// Phase represents one day's work in the campaign.
type Phase struct {
	Day         int       `json:"day"`
	Name        string    `json:"name"`
	Status      string    `json:"status"` // "pending" | "running" | "complete"
	Results     string    `json:"results"`
	CompletedAt time.Time `json:"completed_at"`
}

// ─── Phase Definitions ────────────────────────────────────────────────────────

// phaseDefinitions returns the canonical 7-day phase schedule.
func phaseDefinitions() []Phase {
	return []Phase{
		{Day: 1, Name: "OSINT", Status: "pending"},
		{Day: 2, Name: "Phishing Prep", Status: "pending"},
		{Day: 3, Name: "Initial Access", Status: "pending"},
		{Day: 4, Name: "Lateral Movement", Status: "pending"},
		{Day: 5, Name: "Lateral Movement (continued)", Status: "pending"},
		{Day: 6, Name: "Persistence", Status: "pending"},
		{Day: 7, Name: "Report", Status: "pending"},
	}
}

// phaseObjectives returns the objectives string for a given day.
func phaseObjectives(day int) string {
	switch day {
	case 1:
		return "Passive intelligence gathering on the company"
	case 2:
		return "Generate pretexts, identify targets, craft lure templates"
	case 3:
		return "Credential stuffing, phishing simulation, exposed service exploitation"
	case 4:
		return "Internal network mapping, privilege escalation paths"
	case 5:
		return "Continue lateral movement, deepen access"
	case 6:
		return "Identify persistence mechanisms, simulate implant placement"
	case 7:
		return "Generate full red team report with timeline, findings, and recommendations"
	default:
		return ""
	}
}

// phaseEstimatedDuration returns the estimated duration string for a given day.
func phaseEstimatedDuration(day int) string {
	switch day {
	case 1:
		return "4-6 hours"
	case 2:
		return "3-5 hours"
	case 3:
		return "6-8 hours"
	case 4:
		return "6-8 hours"
	case 5:
		return "6-8 hours"
	case 6:
		return "4-6 hours"
	case 7:
		return "3-4 hours"
	default:
		return "unknown"
	}
}

// ─── Scope Validation ─────────────────────────────────────────────────────────

// checkAuthorization returns true only when input is exactly "yes" (case-insensitive).
// This is a pure function extracted for testability.
func checkAuthorization(input string) bool {
	return strings.ToLower(strings.TrimSpace(input)) == "yes"
}

// ValidateScope prompts the user for scope confirmation.
// Returns error if user does not confirm written authorization.
func ValidateScope(company string) (Scope, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("\n  ⚠️  SCOPE VALIDATION — %s\n", company)
	fmt.Println("  " + strings.Repeat("─", 60))

	// 1. Confirm company name
	fmt.Printf("  Confirm target company [%s]: ", company)
	confirmedCompany, _ := reader.ReadString('\n')
	confirmedCompany = strings.TrimSpace(confirmedCompany)
	if confirmedCompany == "" {
		confirmedCompany = company
	}

	// 2. Authorized IP ranges or domains (comma-separated)
	var domains []string
	var ipRanges []string

	fmt.Println("  Enter authorized IP ranges or domains (comma-separated).")
	fmt.Println("  IP ranges must use CIDR notation (e.g. 10.0.0.0/8).")
	for {
		fmt.Print("  Authorized targets: ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			fmt.Println("  At least one target is required.")
			continue
		}

		parts := strings.Split(line, ",")
		valid := true
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// Check if it looks like a CIDR range
			if strings.Contains(p, "/") {
				if !validateCIDR(p) {
					fmt.Printf("  Invalid IP range: %s — use CIDR notation (e.g. 10.0.0.0/8)\n", p)
					valid = false
					break
				}
				ipRanges = append(ipRanges, p)
			} else {
				domains = append(domains, p)
			}
		}
		if valid && (len(domains) > 0 || len(ipRanges) > 0) {
			break
		}
		if valid {
			fmt.Println("  At least one target is required.")
		}
	}

	// 3. Engagement start and end dates
	fmt.Print("  Engagement start date (YYYY-MM-DD): ")
	startDate, _ := reader.ReadString('\n')
	startDate = strings.TrimSpace(startDate)

	fmt.Print("  Engagement end date (YYYY-MM-DD): ")
	endDate, _ := reader.ReadString('\n')
	endDate = strings.TrimSpace(endDate)

	// 4. Written authorization confirmation
	fmt.Println()
	fmt.Println("  ⚠️  LEGAL NOTICE: You must have written authorization to conduct this engagement.")
	fmt.Print("  Do you have written authorization to test this target? (yes/no): ")
	authInput, _ := reader.ReadString('\n')
	authInput = strings.TrimSpace(authInput)

	if !checkAuthorization(authInput) {
		return Scope{}, fmt.Errorf("Scope validation failed. Written authorization is required.")
	}

	scope := Scope{
		Domains:       domains,
		IPRanges:      ipRanges,
		AuthConfirmed: true,
		StartDate:     startDate,
		EndDate:       endDate,
	}

	fmt.Println()
	fmt.Printf("  ✓ Scope validated for %s\n", confirmedCompany)
	fmt.Printf("  ✓ Domains: %s\n", strings.Join(domains, ", "))
	if len(ipRanges) > 0 {
		fmt.Printf("  ✓ IP Ranges: %s\n", strings.Join(ipRanges, ", "))
	}
	fmt.Printf("  ✓ Engagement: %s → %s\n", startDate, endDate)
	fmt.Println()

	return scope, nil
}

// validateCIDR returns true if s is valid CIDR notation.
func validateCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// ─── State Persistence ────────────────────────────────────────────────────────

// campaignStateDir returns the path to ~/.cybermind/campaigns/
func campaignStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cybermind", "campaigns"), nil
}

// campaignStateFile returns the state file path for a given company and date.
func campaignStateFile(company string, date time.Time) (string, error) {
	dir, err := campaignStateDir()
	if err != nil {
		return "", err
	}
	dateStr := date.Format("2006-01-02")
	// Sanitize company name for use in filename
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, company)
	return filepath.Join(dir, fmt.Sprintf("%s_%s.json", safe, dateStr)), nil
}

// saveCampaignState writes the campaign state to disk.
func saveCampaignState(c *Campaign) error {
	dir, err := campaignStateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.StateFile, data, 0600)
}

// loadCampaignState loads campaign state from a file path.
// Returns nil, nil if the file does not exist.
// Returns nil, err if the file is corrupt.
func loadCampaignState(path string) (*Campaign, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c Campaign
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	c.StateFile = path
	return &c, nil
}

// findExistingStateFile looks for an existing campaign state file for the given company.
// Returns the path of the most recent state file, or "" if none found.
func findExistingStateFile(company string) string {
	dir, err := campaignStateDir()
	if err != nil {
		return ""
	}
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, company)
	pattern := filepath.Join(dir, safe+"_*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	// Return the most recent (lexicographically last, since dates are YYYY-MM-DD)
	latest := matches[0]
	for _, m := range matches[1:] {
		if m > latest {
			latest = m
		}
	}
	return latest
}

// ─── Phase Scheduling ─────────────────────────────────────────────────────────

// getNextIncompletePhase returns the lowest-day phase that is not "complete".
// Returns nil if all phases are complete.
func getNextIncompletePhase(phases []Phase) *Phase {
	// Find the minimum day among incomplete phases
	var next *Phase
	for i := range phases {
		if phases[i].Status != "complete" {
			if next == nil || phases[i].Day < next.Day {
				next = &phases[i]
			}
		}
	}
	return next
}

// ─── Main Engine ──────────────────────────────────────────────────────────────

// RunCampaign executes or resumes a red team campaign.
// Loads state from ~/.cybermind/campaigns/<company>_<date>.json if it exists.
func RunCampaign(company string, duration int) error {
	if duration <= 0 {
		duration = 7
	}

	var campaign *Campaign

	// Try to load existing state
	existingPath := findExistingStateFile(company)
	if existingPath != "" {
		loaded, err := loadCampaignState(existingPath)
		if err != nil {
			fmt.Printf("  ⚠️  Warning: corrupt state file (%s) — starting fresh campaign\n", err)
			campaign = nil
		} else if loaded != nil {
			campaign = loaded
			fmt.Printf("  ↩  Resuming campaign for %s from %s\n", company, existingPath)
		}
	}

	// Start fresh if no existing state
	if campaign == nil {
		// Validate scope before starting
		scope, err := ValidateScope(company)
		if err != nil {
			return err
		}

		stateFile, err := campaignStateFile(company, time.Now())
		if err != nil {
			return fmt.Errorf("failed to determine state file path: %w", err)
		}

		campaign = &Campaign{
			Company:   company,
			Duration:  duration,
			Scope:     scope,
			Phases:    phaseDefinitions(),
			StartDate: time.Now(),
			StateFile: stateFile,
		}

		// Save initial state
		if err := saveCampaignState(campaign); err != nil {
			fmt.Printf("  ⚠️  Warning: could not save initial state: %v\n", err)
		}
	}

	// Build scope map for API calls
	scopeMap := map[string]interface{}{
		"domains":   campaign.Scope.Domains,
		"ip_ranges": campaign.Scope.IPRanges,
	}

	// Collect prior summaries as we go
	var priorSummaries []string
	for _, ph := range campaign.Phases {
		if ph.Status == "complete" && ph.Results != "" {
			priorSummaries = append(priorSummaries, fmt.Sprintf("Day %d (%s): %s", ph.Day, ph.Name, ph.Results[:min(200, len(ph.Results))]))
		}
	}

	// Execute phases in ascending day order
	for {
		next := getNextIncompletePhase(campaign.Phases)
		if next == nil {
			fmt.Println("\n  ✅ All phases complete!")
			break
		}

		// Display daily banner
		fmt.Printf("\n  ╔══════════════════════════════════════════════════════════╗\n")
		fmt.Printf("  ║  DAY %d — %s\n", next.Day, next.Name)
		fmt.Printf("  ║  Objectives: %s\n", phaseObjectives(next.Day))
		fmt.Printf("  ║  Estimated duration: %s\n", phaseEstimatedDuration(next.Day))
		fmt.Printf("  ╚══════════════════════════════════════════════════════════╝\n\n")

		// Mark phase as running
		for i := range campaign.Phases {
			if campaign.Phases[i].Day == next.Day {
				campaign.Phases[i].Status = "running"
				break
			}
		}

		// POST to /api/red-team/phase
		fmt.Printf("  ⟳ Requesting AI guidance for Day %d...\n", next.Day)
		result, err := api.SendRedTeamPhase(company, next.Day, scopeMap, priorSummaries)
		if err != nil {
			fmt.Printf("  ⚠️  AI guidance failed: %v\n", err)
			result = fmt.Sprintf("Day %d phase could not retrieve AI guidance: %v", next.Day, err)
		}

		// Display result
		fmt.Printf("\n  📋 Day %d Guidance:\n%s\n", next.Day, result)

		// Mark phase complete and record results
		for i := range campaign.Phases {
			if campaign.Phases[i].Day == next.Day {
				campaign.Phases[i].Status = "complete"
				campaign.Phases[i].Results = result
				campaign.Phases[i].CompletedAt = time.Now()
				break
			}
		}

		// Add to prior summaries for next phase
		if len(result) > 200 {
			priorSummaries = append(priorSummaries, fmt.Sprintf("Day %d (%s): %s...", next.Day, next.Name, result[:200]))
		} else {
			priorSummaries = append(priorSummaries, fmt.Sprintf("Day %d (%s): %s", next.Day, next.Name, result))
		}

		// Save phase results to Brain_Memory
		mem := brain.LoadTarget(company)
		mem.Notes += fmt.Sprintf("\n[Day %d - %s]\n%s\n", next.Day, next.Name, result)
		if err := brain.SaveTarget(mem); err != nil {
			fmt.Printf("  ⚠️  Warning: could not save to Brain_Memory: %v\n", err)
		}
		if err := storage.AddEntry(fmt.Sprintf("/red-team %s day%d", company, next.Day), result); err != nil {
			fmt.Printf("  ⚠️  Warning: could not save to history: %v\n", err)
		}

		// Save state after each phase
		if err := saveCampaignState(campaign); err != nil {
			fmt.Printf("  ⚠️  Warning: could not save campaign state: %v\n", err)
		}

		fmt.Printf("  ✓ Day %d complete\n", next.Day)

		// On Day 7 completion, generate report
		if next.Day == 7 {
			if err := generateReport(campaign); err != nil {
				fmt.Printf("  ⚠️  Warning: could not generate report: %v\n", err)
			}
		}
	}

	return nil
}

// generateReport writes the final red team report to a markdown file.
func generateReport(c *Campaign) error {
	dateStr := c.StartDate.Format("2006-01-02")
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, c.Company)
	filename := fmt.Sprintf("redteam_%s_%s.md", safe, dateStr)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Red Team Report — %s\n\n", c.Company))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", dateStr))
	sb.WriteString(fmt.Sprintf("**Duration:** %d days\n\n", c.Duration))
	sb.WriteString("## Scope\n\n")
	if len(c.Scope.Domains) > 0 {
		sb.WriteString(fmt.Sprintf("**Domains:** %s\n\n", strings.Join(c.Scope.Domains, ", ")))
	}
	if len(c.Scope.IPRanges) > 0 {
		sb.WriteString(fmt.Sprintf("**IP Ranges:** %s\n\n", strings.Join(c.Scope.IPRanges, ", ")))
	}
	sb.WriteString(fmt.Sprintf("**Engagement Period:** %s → %s\n\n", c.Scope.StartDate, c.Scope.EndDate))
	sb.WriteString("## Phase Results\n\n")

	for _, ph := range c.Phases {
		sb.WriteString(fmt.Sprintf("### Day %d — %s\n\n", ph.Day, ph.Name))
		sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", ph.Status))
		if ph.Status == "complete" {
			sb.WriteString(fmt.Sprintf("**Completed:** %s\n\n", ph.CompletedAt.Format(time.RFC3339)))
			sb.WriteString(ph.Results)
			sb.WriteString("\n\n")
		}
	}

	if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
		return err
	}
	fmt.Printf("\n  📄 Report saved: %s\n", filename)
	return nil
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
