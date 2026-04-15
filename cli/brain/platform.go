// platform.go — H1/BC API Integration
// HackerOne + Bugcrowd: fetch programs, scope, check duplicates, auto-submit.
package brain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── Credentials ─────────────────────────────────────────────────────────────

// PlatformCredentials holds API tokens for bug bounty platforms.
type PlatformCredentials struct {
	H1Username string `json:"h1_username"`
	H1Token    string `json:"h1_token"`
	BCEmail    string `json:"bc_email"`
	BCToken    string `json:"bc_token"`
}

func credsFile() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cybermind", "platform_creds.json")
}

// SaveCredentials saves platform API credentials securely.
func SaveCredentials(creds PlatformCredentials) error {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cybermind")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	return os.WriteFile(credsFile(), data, 0600) // owner-only read
}

// LoadCredentials loads saved platform credentials.
func LoadCredentials() (*PlatformCredentials, error) {
	data, err := os.ReadFile(credsFile())
	if err != nil {
		return nil, err
	}
	var creds PlatformCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// HasCredentials returns true if any platform credentials are saved.
func HasCredentials() bool {
	creds, err := LoadCredentials()
	if err != nil {
		return false
	}
	return creds.H1Token != "" || creds.BCToken != ""
}

// ─── HackerOne API ────────────────────────────────────────────────────────────

const h1BaseURL = "https://api.hackerone.com/v1"

// H1Program represents a HackerOne bug bounty program.
type H1Program struct {
	Handle      string     `json:"handle"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Scope       []H1Scope  `json:"structured_scopes"`
	BountyTable H1Bounty   `json:"bounty_table"`
	ResponseEff float64    `json:"response_efficiency_percentage"`
}

// H1Scope represents a scope entry in a HackerOne program.
type H1Scope struct {
	AssetType       string `json:"asset_type"`
	AssetIdentifier string `json:"asset_identifier"`
	EligibleForBounty bool `json:"eligible_for_bounty"`
	MaxSeverity     string `json:"max_severity"`
	InScope         bool   `json:"eligible_for_submission"`
}

// H1Bounty holds bounty amounts.
type H1Bounty struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
}

// H1Report is the structure for submitting a bug report.
type H1Report struct {
	TeamHandle              string `json:"team_handle"`
	Title                   string `json:"title"`
	VulnerabilityInfo       string `json:"vulnerability_information"`
	SeverityRating          string `json:"severity_rating"` // none, low, medium, high, critical
	Impact                  string `json:"impact"`
	WeaknessID              int    `json:"weakness_id,omitempty"`
}

// H1SubmitResult holds the result of a report submission.
type H1SubmitResult struct {
	ReportID  string
	URL       string
	Status    string
	Error     string
}

// FetchH1Programs fetches programs the user participates in.
func FetchH1Programs(creds *PlatformCredentials) ([]H1Program, error) {
	if creds.H1Token == "" {
		return nil, fmt.Errorf("no HackerOne token configured")
	}
	req, err := http.NewRequest("GET", h1BaseURL+"/hackers/me/programs?page[size]=100", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(creds.H1Username, creds.H1Token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach HackerOne API: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var result struct {
		Data []struct {
			Attributes H1Program `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid H1 response: %v", err)
	}
	var programs []H1Program
	for _, d := range result.Data {
		programs = append(programs, d.Attributes)
	}
	return programs, nil
}

// FetchH1ProgramScope fetches the full scope for a specific program.
func FetchH1ProgramScope(creds *PlatformCredentials, handle string) (*ProgramScope, error) {
	if creds.H1Token == "" {
		return nil, fmt.Errorf("no HackerOne token configured")
	}
	url := fmt.Sprintf("%s/programs/%s", h1BaseURL, handle)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(creds.H1Username, creds.H1Token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var result struct {
		Data struct {
			Attributes struct {
				Name             string     `json:"name"`
				Handle           string     `json:"handle"`
				StructuredScopes []H1Scope  `json:"structured_scopes"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	scope := &ProgramScope{
		ProgramName: result.Data.Attributes.Name,
		Handle:      result.Data.Attributes.Handle,
		Platform:    "hackerone",
		LastFetched: time.Now(),
	}
	for _, s := range result.Data.Attributes.StructuredScopes {
		target := ScopeTarget{
			Domain:  s.AssetIdentifier,
			InScope: s.InScope && s.EligibleForBounty,
		}
		if strings.HasPrefix(s.AssetIdentifier, "*.") {
			target.Type = "wildcard"
		} else if strings.HasPrefix(s.AssetIdentifier, "http") {
			target.Type = "url"
			target.URL = s.AssetIdentifier
		} else {
			target.Type = "domain"
		}
		if s.InScope {
			scope.InScope = append(scope.InScope, target)
		} else {
			scope.OutScope = append(scope.OutScope, target)
		}
	}
	return scope, nil
}

// CheckH1Duplicate checks if a similar bug was already reported on H1.
func CheckH1Duplicate(creds *PlatformCredentials, handle, bugTitle, url string) (bool, string) {
	if creds.H1Token == "" {
		return false, ""
	}
	apiURL := fmt.Sprintf("%s/reports?filter[program][]=%s&filter[state][]=new&filter[state][]=triaged&page[size]=25",
		h1BaseURL, handle)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, ""
	}
	req.SetBasicAuth(creds.H1Username, creds.H1Token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Title string `json:"title"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, ""
	}

	bugLower := strings.ToLower(bugTitle)
	urlLower := strings.ToLower(url)
	for _, r := range result.Data {
		titleLower := strings.ToLower(r.Attributes.Title)
		// Check for similar title or URL in title
		if strings.Contains(titleLower, bugLower[:min(20, len(bugLower))]) ||
			strings.Contains(titleLower, urlLower) {
			return true, fmt.Sprintf("https://hackerone.com/reports/%s", r.ID)
		}
	}
	return false, ""
}

// SubmitH1Report submits a bug report to HackerOne.
func SubmitH1Report(creds *PlatformCredentials, report H1Report) (*H1SubmitResult, error) {
	if creds.H1Token == "" {
		return nil, fmt.Errorf("no HackerOne token configured")
	}

	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "report",
			"attributes": map[string]interface{}{
				"team_handle":               report.TeamHandle,
				"title":                     report.Title,
				"vulnerability_information": report.VulnerabilityInfo,
				"severity_rating":           report.SeverityRating,
				"impact":                    report.Impact,
			},
		},
	}
	if report.WeaknessID > 0 {
		payload["data"].(map[string]interface{})["relationships"] = map[string]interface{}{
			"weakness": map[string]interface{}{
				"data": map[string]interface{}{
					"type": "weakness",
					"id":   fmt.Sprintf("%d", report.WeaknessID),
				},
			},
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", h1BaseURL+"/reports", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(creds.H1Username, creds.H1Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach HackerOne: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
		Errors []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("invalid response: %v", err)
	}
	if len(result.Errors) > 0 {
		return &H1SubmitResult{Error: result.Errors[0].Detail}, nil
	}
	return &H1SubmitResult{
		ReportID: result.Data.ID,
		URL:      fmt.Sprintf("https://hackerone.com/reports/%s", result.Data.ID),
		Status:   "submitted",
	}, nil
}

// ─── Bugcrowd API ─────────────────────────────────────────────────────────────

const bcBaseURL = "https://bugcrowd.com/api/v1"

// BCProgram represents a Bugcrowd program.
type BCProgram struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	ProgramURL  string `json:"program_url"`
	MaxPayout   int    `json:"max_payout"`
}

// FetchBCPrograms fetches Bugcrowd programs.
func FetchBCPrograms(creds *PlatformCredentials) ([]BCProgram, error) {
	if creds.BCToken == "" {
		return nil, fmt.Errorf("no Bugcrowd token configured")
	}
	req, err := http.NewRequest("GET", bcBaseURL+"/programs?page[limit]=50", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+creds.BCToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach Bugcrowd API: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	var result struct {
		Data []struct {
			Attributes BCProgram `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	var programs []BCProgram
	for _, d := range result.Data {
		programs = append(programs, d.Attributes)
	}
	return programs, nil
}

// ─── Auto-Submit Pipeline ─────────────────────────────────────────────────────

// AutoSubmitBug automatically submits a confirmed bug to the appropriate platform.
// Returns the report URL if successful.
func AutoSubmitBug(bug Bug, programHandle, platform string) (string, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return "", fmt.Errorf("no platform credentials — run: cybermind /platform --setup")
	}

	// Build report content
	report := buildReportContent(bug)

	switch platform {
	case "hackerone":
		// Check for duplicates first
		isDup, dupURL := CheckH1Duplicate(creds, programHandle, bug.Title, bug.URL)
		if isDup {
			return "", fmt.Errorf("duplicate: similar report exists at %s", dupURL)
		}
		h1Report := H1Report{
			TeamHandle:        programHandle,
			Title:             bug.Title,
			VulnerabilityInfo: report,
			SeverityRating:    bug.Severity,
			Impact:            buildImpactStatement(bug),
		}
		result, err := SubmitH1Report(creds, h1Report)
		if err != nil {
			return "", err
		}
		if result.Error != "" {
			return "", fmt.Errorf("H1 error: %s", result.Error)
		}
		return result.URL, nil

	default:
		return "", fmt.Errorf("platform %q not supported yet", platform)
	}
}

// buildReportContent generates a professional bug report from a Bug.
func buildReportContent(bug Bug) string {
	var sb strings.Builder
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("A **%s** vulnerability was found at `%s`.\n\n", bug.Type, bug.URL))

	sb.WriteString("## Steps to Reproduce\n\n")
	sb.WriteString("1. Navigate to the vulnerable endpoint\n")
	sb.WriteString(fmt.Sprintf("2. URL: `%s`\n", bug.URL))
	if bug.PoC != "" {
		sb.WriteString(fmt.Sprintf("3. Payload/PoC:\n```\n%s\n```\n", bug.PoC))
	}
	sb.WriteString("\n## Evidence\n\n")
	sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", bug.Evidence))

	sb.WriteString("## Impact\n\n")
	sb.WriteString(buildImpactStatement(bug))
	sb.WriteString("\n\n## Tool\n\n")
	sb.WriteString(fmt.Sprintf("Discovered using: %s\n", bug.Tool))
	sb.WriteString("\n---\n*Report generated by CyberMind AI Bug Bounty Agent*\n")
	return sb.String()
}

// buildImpactStatement generates an impact description based on bug type.
func buildImpactStatement(bug Bug) string {
	impacts := map[string]string{
		"xss":           "An attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking, credential theft, or malicious redirects.",
		"sqli":          "An attacker can read, modify, or delete database contents, potentially accessing sensitive user data, credentials, or business information.",
		"ssrf":          "An attacker can make the server perform requests to internal services, potentially accessing cloud metadata, internal APIs, or sensitive infrastructure.",
		"idor":          "An attacker can access or modify resources belonging to other users by manipulating object identifiers, leading to unauthorized data access.",
		"rce":           "An attacker can execute arbitrary commands on the server, leading to complete system compromise.",
		"lfi":           "An attacker can read arbitrary files from the server filesystem, potentially exposing credentials, source code, or sensitive configuration.",
		"open-redirect": "An attacker can redirect users to malicious websites, enabling phishing attacks.",
		"ssti":          "An attacker can inject template expressions that execute on the server, potentially leading to remote code execution.",
		"xxe":           "An attacker can read internal files or perform SSRF attacks via XML external entity injection.",
	}
	if impact, ok := impacts[strings.ToLower(bug.Type)]; ok {
		return impact
	}
	return fmt.Sprintf("This %s vulnerability could allow an attacker to compromise the security of the application.", bug.Type)
}

// ─── Public Scope Fetcher (no auth needed) ────────────────────────────────────

// PublicProgramScope holds scope data fetched without authentication
type PublicProgramScope struct {
	Handle   string
	Name     string
	InScope  []string
	OutScope []string
	URL      string
}

// FetchPublicScope fetches a program's scope using HackerOne's public GraphQL API.
// No authentication required — works for any public program.
func FetchPublicScope(handle string) (*PublicProgramScope, error) {
	// HackerOne public GraphQL endpoint
	query := `{"query":"{ team(handle: \"` + handle + `\") { name handle url structured_scopes(first: 100, eligible_for_submission: true) { edges { node { asset_type asset_identifier eligible_for_bounty max_severity } } } } }"}`

	req, err := http.NewRequest("POST", "https://hackerone.com/graphql", bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("X-Auth-Token", "") // public endpoint

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach HackerOne: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var result struct {
		Data struct {
			Team struct {
				Name   string `json:"name"`
				Handle string `json:"handle"`
				URL    string `json:"url"`
				StructuredScopes struct {
					Edges []struct {
						Node struct {
							AssetType       string `json:"asset_type"`
							AssetIdentifier string `json:"asset_identifier"`
							EligibleBounty  bool   `json:"eligible_for_bounty"`
							MaxSeverity     string `json:"max_severity"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"structured_scopes"`
			} `json:"team"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid response: %v", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
	}

	team := result.Data.Team
	if team.Handle == "" {
		return nil, fmt.Errorf("program '%s' not found or not public", handle)
	}

	scope := &PublicProgramScope{
		Handle: team.Handle,
		Name:   team.Name,
		URL:    "https://hackerone.com/" + team.Handle,
	}

	for _, edge := range team.StructuredScopes.Edges {
		node := edge.Node
		if node.AssetType == "URL" || node.AssetType == "WILDCARD" || node.AssetType == "DOMAIN" {
			scope.InScope = append(scope.InScope, node.AssetIdentifier)
		}
	}

	return scope, nil
}

// FetchPublicScopeTargets returns a flat list of testable domains from a public program
func FetchPublicScopeTargets(handle string) ([]string, error) {
	scope, err := FetchPublicScope(handle)
	if err != nil {
		return nil, err
	}
	return scope.InScope, nil
}
