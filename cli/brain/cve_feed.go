// cve_feed.go — Real-time CVE Intelligence Feed
// Fetches latest CVEs from NVD, matches against detected tech stack,
// auto-selects nuclei templates, and triggers targeted exploitation.
package brain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CVEEntry represents a CVE from NVD
type CVEEntry struct {
	ID             string
	Description    string
	CVSS           float64
	Severity       string
	Published      time.Time
	Products       []string
	References     []string
	NucleiTemplate string
	Exploitable    bool
}

// CVEMatchResult holds CVEs matched to a target's tech stack
type CVEMatchResult struct {
	Target     string
	TechStack  []string
	Matched    []CVEEntry
	TotalFound int
	FetchedAt  time.Time
}

var cveClient = &http.Client{Timeout: 30 * time.Second}

// FetchLatestCVEs fetches CVEs from NVD published in the last N days
func FetchLatestCVEs(days int) ([]CVEEntry, error) {
	end := time.Now()
	start := end.AddDate(0, 0, -days)
	nvdURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&cvssV3Severity=CRITICAL,HIGH&resultsPerPage=100",
		start.Format("2006-01-02T15:04:05"),
		end.Format("2006-01-02T15:04:05"),
	)
	req, err := http.NewRequest("GET", nvdURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CyberMind-CVE-Feed/4.2")
	resp, err := cveClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	return parseNVDResponse(body)
}

// FetchCVEByID fetches a specific CVE by ID
func FetchCVEByID(cveID string) (*CVEEntry, error) {
	resp, err := cveClient.Get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	entries, err := parseNVDResponse(body)
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}
	return &entries[0], nil
}

func parseNVDResponse(body []byte) ([]CVEEntry, error) {
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("NVD parse error: %v", err)
	}
	var entries []CVEEntry
	for _, v := range nvdResp.Vulnerabilities {
		cve := v.CVE
		entry := CVEEntry{ID: cve.ID}
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				entry.Description = d.Value
				break
			}
		}
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			entry.CVSS = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			entry.Severity = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			entry.CVSS = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			entry.Severity = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		}
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, cpe := range node.CPEMatch {
					parts := strings.Split(cpe.Criteria, ":")
					if len(parts) >= 5 && parts[3] != "*" && parts[4] != "*" {
						entry.Products = append(entry.Products, parts[3]+":"+parts[4])
					}
				}
			}
		}
		for _, ref := range cve.References {
			entry.References = append(entry.References, ref.URL)
			lower := strings.ToLower(ref.URL)
			if strings.Contains(lower, "exploit") || strings.Contains(lower, "poc") {
				entry.Exploitable = true
			}
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
			entry.Published = t
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// MatchCVEsToTarget matches CVEs against a target's detected tech stack
func MatchCVEsToTarget(target string, techStack []string, shodanVulns string) CVEMatchResult {
	result := CVEMatchResult{Target: target, TechStack: techStack, FetchedAt: time.Now()}

	// Check Shodan vulns first
	if shodanVulns != "" {
		for _, cveID := range strings.Split(shodanVulns, ",") {
			cveID = strings.TrimSpace(cveID)
			if !strings.HasPrefix(cveID, "CVE-") {
				continue
			}
			entry, err := FetchCVEByID(cveID)
			if err == nil && entry != nil {
				entry.NucleiTemplate = findNucleiTemplate(cveID)
				result.Matched = append(result.Matched, *entry)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Fetch recent CVEs and match to tech stack
	recentCVEs, err := FetchLatestCVEs(30)
	if err == nil {
		for _, cve := range recentCVEs {
			if matchesTechStack(cve, techStack) {
				cve.NucleiTemplate = findNucleiTemplate(cve.ID)
				result.Matched = append(result.Matched, cve)
			}
		}
	}

	// Tech-specific CVE searches
	for _, tech := range techStack {
		techCVEs := fetchTechSpecificCVEs(tech)
		for _, cve := range techCVEs {
			isDup := false
			for _, existing := range result.Matched {
				if existing.ID == cve.ID {
					isDup = true
					break
				}
			}
			if !isDup {
				cve.NucleiTemplate = findNucleiTemplate(cve.ID)
				result.Matched = append(result.Matched, cve)
			}
		}
	}

	result.TotalFound = len(result.Matched)
	return result
}

func fetchTechSpecificCVEs(tech string) []CVEEntry {
	techKeywords := map[string]string{
		"wordpress": "wordpress", "apache": "apache http server",
		"nginx": "nginx", "php": "php", "node": "node.js",
		"django": "django", "flask": "flask", "spring": "spring framework",
		"tomcat": "apache tomcat", "log4j": "log4j", "struts": "apache struts",
		"jenkins": "jenkins", "grafana": "grafana", "redis": "redis",
		"mongodb": "mongodb", "mysql": "mysql", "postgresql": "postgresql",
	}
	techLower := strings.ToLower(tech)
	keyword := ""
	for k, v := range techKeywords {
		if strings.Contains(techLower, k) {
			keyword = v
			break
		}
	}
	if keyword == "" {
		return nil
	}
	nvdURL := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&cvssV3Severity=CRITICAL,HIGH&resultsPerPage=20",
		strings.ReplaceAll(keyword, " ", "%20"),
	)
	resp, err := cveClient.Get(nvdURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}
	entries, _ := parseNVDResponse(body)
	return entries
}

func matchesTechStack(cve CVEEntry, techStack []string) bool {
	descLower := strings.ToLower(cve.Description)
	for _, tech := range techStack {
		techName := strings.ToLower(strings.Split(strings.Split(tech, ":")[0], " ")[0])
		if strings.Contains(descLower, techName) {
			return true
		}
		for _, product := range cve.Products {
			if strings.Contains(strings.ToLower(product), techName) {
				return true
			}
		}
	}
	return false
}

func findNucleiTemplate(cveID string) string {
	templateDirs := []string{
		os.Getenv("HOME") + "/nuclei-templates/cves/",
		"/root/nuclei-templates/cves/",
	}
	cveYear := ""
	if len(cveID) >= 8 {
		cveYear = cveID[4:8]
	}
	for _, dir := range templateDirs {
		yearDir := dir + cveYear + "/"
		if _, err := os.Stat(yearDir); err == nil {
			entries, err := os.ReadDir(yearDir)
			if err == nil {
				cveIDLower := strings.ToLower(cveID)
				for _, entry := range entries {
					if strings.Contains(strings.ToLower(entry.Name()), cveIDLower) {
						return yearDir + entry.Name()
					}
				}
			}
		}
	}
	return ""
}

// RunCVEExploitation runs nuclei templates for matched CVEs
func RunCVEExploitation(target string, cves []CVEEntry, onResult func(cveID, result string)) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		onResult("nuclei", "nuclei not installed")
		return
	}
	for _, cve := range cves {
		templateArg := ""
		if cve.NucleiTemplate != "" {
			templateArg = cve.NucleiTemplate
		} else {
			templateArg = strings.ToLower(cve.ID)
		}
		var cmd *exec.Cmd
		if cve.NucleiTemplate != "" {
			cmd = exec.Command("nuclei", "-u", target, "-t", templateArg, "-silent", "-no-color", "-timeout", "30")
		} else {
			cmd = exec.Command("nuclei", "-u", target, "-tags", templateArg, "-silent", "-no-color", "-timeout", "30")
		}
		cmd.Stdin = nil
		out, err := runWithTimeout(cmd, 60)
		if err == nil && strings.TrimSpace(out) != "" {
			onResult(cve.ID, out)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// FormatCVEReport returns a human-readable CVE match report
func FormatCVEReport(result CVEMatchResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  🔴 CVE Intelligence — %s\n", result.Target))
	if len(result.TechStack) > 0 {
		n := len(result.TechStack)
		if n > 5 {
			n = 5
		}
		sb.WriteString(fmt.Sprintf("  Tech: %s\n", strings.Join(result.TechStack[:n], ", ")))
	}
	sb.WriteString(fmt.Sprintf("  Matched CVEs: %d\n\n", result.TotalFound))
	if result.TotalFound == 0 {
		sb.WriteString("  No CVEs matched for detected tech stack.\n")
		return sb.String()
	}
	// Sort by CVSS
	sorted := make([]CVEEntry, len(result.Matched))
	copy(sorted, result.Matched)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].CVSS > sorted[i].CVSS {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for i, cve := range sorted {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(sorted)-20))
			break
		}
		flags := ""
		if cve.Exploitable {
			flags += " [EXPLOIT]"
		}
		if cve.NucleiTemplate != "" {
			flags += " [NUCLEI]"
		}
		sb.WriteString(fmt.Sprintf("  [%.1f %s] %s%s\n", cve.CVSS, cve.Severity, cve.ID, flags))
		if cve.Description != "" {
			desc := cve.Description
			if len(desc) > 120 {
				desc = desc[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("    %s\n", desc))
		}
	}
	return sb.String()
}
