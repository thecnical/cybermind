package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// capitalize returns s with the first letter uppercased and the rest lowercased.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// domainRe matches valid hostnames/subdomains
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$`)

// addSubdomain validates and adds a hostname to the seen map and slice
func addSubdomain(line string, seen map[string]bool, subs *[]string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return
	}
	// Extract hostname from lines like "sub.example.com [1.2.3.4]" or just "sub.example.com"
	host := line
	if idx := strings.IndexAny(line, " \t["); idx > 0 {
		host = line[:idx]
	}
	host = strings.TrimSpace(host)
	if host != "" && domainRe.MatchString(host) && !seen[host] {
		seen[host] = true
		*subs = append(*subs, host)
	}
}

// readReconFTWSubdomains reads all subdomain files from reconftw's structured output directory.
// reconftw writes results to: <outdir>/subdomains/subdomains.txt and related files.
// This gives us the FULL reconftw subdomain coverage — passive + brute + permutations + cert transparency.
func readReconFTWSubdomains(target string, seen map[string]bool, subs *[]string) {
	// reconftw output directory pattern
	outDirs := []string{
		"/tmp/cybermind_reconftw_" + target,
		"/tmp/cybermind_reconftw/" + target,
		"/opt/reconftw/Recon/" + target,
	}

	// All subdomain files reconftw produces
	subFiles := []string{
		"subdomains/subdomains.txt",           // all unique subdomains
		"subdomains/subdomains_alive.txt",     // live subdomains only
		"subdomains/subdomains_resolved.txt",  // DNS-resolved subdomains
		"subdomains/all_subdomains.txt",       // combined all sources
		"subdomains/subdomains_http.txt",      // HTTP-alive subdomains
		"subdomains/subdomains_https.txt",     // HTTPS-alive subdomains
		"subdomains/subdomains_ips.txt",       // subdomains with IPs
		"subdomains/subdomains_takeover.txt",  // takeover candidates
		"subdomains/subdomains_brute.txt",     // brute-forced subdomains
		"subdomains/subdomains_permut.txt",    // permutation-discovered
		"subdomains/subdomains_crt.txt",       // cert transparency
		"subdomains/subdomains_passive.txt",   // passive sources
	}

	for _, dir := range outDirs {
		if _, err := os.Stat(dir); err != nil {
			continue // directory doesn't exist
		}
		for _, sf := range subFiles {
			path := filepath.Join(dir, sf)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				addSubdomain(line, seen, subs)
			}
		}
	}
}

// readReconFTWLiveURLs reads live URL files from reconftw's output directory.
func readReconFTWLiveURLs(target string) []string {
	var urls []string
	seen := map[string]bool{}

	outDirs := []string{
		"/tmp/cybermind_reconftw_" + target,
		"/tmp/cybermind_reconftw/" + target,
		"/opt/reconftw/Recon/" + target,
	}

	urlFiles := []string{
		"webs/webs.txt",           // all live web targets
		"webs/webs_all.txt",       // all web targets including uncommon ports
		"webs/webs_alive.txt",     // confirmed alive
		"webs/webs_urls.txt",      // collected URLs
		"webs/urls.txt",           // URL list
		"webs/katana.txt",         // katana crawled URLs
		"webs/waymore.txt",        // waymore passive URLs
	}

	for _, dir := range outDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		for _, uf := range urlFiles {
			path := filepath.Join(dir, uf)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && strings.HasPrefix(line, "http") && !seen[line] {
					seen[line] = true
					urls = append(urls, line)
				}
			}
		}
	}
	return urls
}

// readReconFTWVulns reads vulnerability findings from reconftw's output directory.
func readReconFTWVulns(target string) []string {
	var vulns []string
	seen := map[string]bool{}

	outDirs := []string{
		"/tmp/cybermind_reconftw_" + target,
		"/tmp/cybermind_reconftw/" + target,
		"/opt/reconftw/Recon/" + target,
	}

	vulnFiles := []string{
		"vulns/vulns.txt",
		"vulns/nuclei.txt",
		"vulns/xss.txt",
		"vulns/sqli.txt",
		"vulns/ssrf.txt",
		"vulns/lfi.txt",
		"vulns/ssti.txt",
		"vulns/crlf.txt",
		"vulns/open_redirect.txt",
		"vulns/cors.txt",
	}

	for _, dir := range outDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		for _, vf := range vulnFiles {
			path := filepath.Join(dir, vf)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !seen[line] {
					seen[line] = true
					vulns = append(vulns, line)
				}
			}
		}
	}
	return vulns
}

// extractSubdomains parses subfinder/amass/reconftw output for subdomain names.
// For reconftw: reads both stdout AND structured output files for maximum coverage.
func extractSubdomains(result ReconResult) []string {
	var subs []string
	seen := map[string]bool{}

	for _, tr := range result.Results {
		switch tr.Tool {
		case "subfinder", "amass":
			for _, line := range strings.Split(tr.Output, "\n") {
				addSubdomain(line, seen, &subs)
			}
		case "reconftw":
			// Parse stdout output
			for _, line := range strings.Split(tr.Output, "\n") {
				addSubdomain(line, seen, &subs)
			}
			// CRITICAL: Also read reconftw's structured output files
			// reconftw writes 10+ subdomain files with different sources
			// This gives us passive + brute + permutations + cert transparency
			// Extract target from output (reconftw prints the target domain)
			for _, line := range strings.Split(tr.Output, "\n") {
				if strings.Contains(line, "Target:") || strings.Contains(line, "domain:") {
					parts := strings.Fields(line)
					for _, p := range parts {
						if domainRe.MatchString(p) {
							readReconFTWSubdomains(p, seen, &subs)
						}
					}
				}
			}
		}
	}
	return subs
}

// extractLiveHosts parses dnsx output lines for resolved hostnames.
func extractLiveHosts(result ReconResult) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "dnsx" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			host := line
			if idx := strings.IndexAny(line, " ["); idx > 0 {
				host = line[:idx]
			}
			host = strings.TrimSpace(host)
			if host != "" && !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// portRe matches port lines like "80/tcp open http"
var portRe = regexp.MustCompile(`(\d+)/tcp\s+open`)

// masscanPortRe matches masscan JSON output: "port": 80
var masscanPortRe = regexp.MustCompile(`"port"\s*:\s*(\d+)`)

// extractOpenPorts parses nmap/rustscan/naabu/masscan output for open port numbers.
func extractOpenPorts(result ReconResult) []int {
	var ports []int
	seen := map[int]bool{}
	for _, tr := range result.Results {
		switch tr.Tool {
		case "nmap", "rustscan", "naabu":
			for _, match := range portRe.FindAllStringSubmatch(tr.Output, -1) {
				if len(match) < 2 {
					continue
				}
				p, err := strconv.Atoi(match[1])
				if err == nil && !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		case "masscan":
			for _, match := range masscanPortRe.FindAllStringSubmatch(tr.Output, -1) {
				if len(match) < 2 {
					continue
				}
				p, err := strconv.Atoi(match[1])
				if err == nil && !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		}
	}
	return ports
}

// wafRe matches nmap http-waf-detect NSE output
var wafRe = regexp.MustCompile(`(?i)http-waf-detect[^\n]*\n[^\n]*detected[^\n]*`)
var wafVendorRe = regexp.MustCompile(`(?i)(cloudflare|akamai|imperva|f5|barracuda|sucuri|incapsula|modsecurity|aws|azure|fastly)`)

// extractWAF scans nmap output for WAF detection.
func extractWAF(result ReconResult) (bool, string) {
	for _, tr := range result.Results {
		if tr.Tool != "nmap" {
			continue
		}
		if wafRe.MatchString(tr.Output) {
			vendor := ""
			if m := wafVendorRe.FindString(tr.Output); m != "" {
				vendor = capitalize(strings.ToLower(m))
			}
			return true, vendor
		}
		lower := strings.ToLower(tr.Output)
		if strings.Contains(lower, "waf") && strings.Contains(lower, "detected") {
			vendor := ""
			if m := wafVendorRe.FindString(tr.Output); m != "" {
				vendor = capitalize(strings.ToLower(m))
			}
			return true, vendor
		}
	}
	return false, ""
}

// urlRe matches URLs with http/https scheme
var urlRe = regexp.MustCompile(`https?://[^\s\[\]]+`)

// extractLiveURLs parses httpx output + reconftw web files for live URLs.
func extractLiveURLs(result ReconResult) []string {
	var urls []string
	seen := map[string]bool{}

	for _, tr := range result.Results {
		switch tr.Tool {
		case "httpx":
			for _, line := range strings.Split(tr.Output, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if m := urlRe.FindString(line); m != "" && !seen[m] {
					seen[m] = true
					urls = append(urls, m)
				}
			}
		case "reconftw":
			// Also read reconftw's web output files for live URLs
			for _, line := range strings.Split(tr.Output, "\n") {
				if strings.Contains(line, "Target:") || strings.Contains(line, "domain:") {
					parts := strings.Fields(line)
					for _, p := range parts {
						if domainRe.MatchString(p) {
							for _, u := range readReconFTWLiveURLs(p) {
								if !seen[u] {
									seen[u] = true
									urls = append(urls, u)
								}
							}
						}
					}
				}
			}
		}
	}
	return urls
}

// extractCrawledURLs parses katana output for discovered endpoints.
func extractCrawledURLs(result ReconResult) []string {
	var urls []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "katana" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if m := urlRe.FindString(line); m != "" && !seen[m] {
				seen[m] = true
				urls = append(urls, m)
			}
		}
	}
	return urls
}

// ensureToolQueued adds a tool to available if not already present.
func ensureToolQueued(name string, available []ToolSpec, registry []ToolSpec) []ToolSpec {
	for _, spec := range available {
		if spec.Name == name {
			return available
		}
	}
	for _, spec := range registry {
		if spec.Name == name {
			return append(available, spec)
		}
	}
	return available
}

// containsPort checks if a port number is in the list
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// buildCombined assembles the combined output string from all tool results.
func buildCombined(result *ReconResult) {
	for _, tr := range result.Results {
		if tr.Tool == "combined" {
			return
		}
	}
	var b strings.Builder
	for _, tr := range result.Results {
		if tr.Tool == "combined" || tr.Output == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tr.Tool), tr.Output))
	}
	if b.Len() > 0 {
		combined := ToolResult{Tool: "combined", Output: b.String()}
		result.Results = append([]ToolResult{combined}, result.Results...)
	}
}
