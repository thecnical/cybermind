package recon

import (
	"fmt"
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

// extractSubdomains parses subfinder/amass/reconftw output lines for subdomain names.
// Each non-empty line that looks like a hostname is treated as a subdomain.
func extractSubdomains(result ReconResult) []string {
	var subs []string
	seen := map[string]bool{}
	// domainRe matches valid hostnames/subdomains
	domainRe := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$`)

	for _, tr := range result.Results {
		if tr.Tool != "subfinder" && tr.Tool != "amass" && tr.Tool != "reconftw" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			// Skip empty lines, comments, paths, and non-hostname lines
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
				continue
			}
			// Extract hostname from lines like "sub.example.com [1.2.3.4]" or just "sub.example.com"
			host := line
			if idx := strings.IndexAny(line, " \t["); idx > 0 {
				host = line[:idx]
			}
			host = strings.TrimSpace(host)
			if host != "" && domainRe.MatchString(host) && !seen[host] {
				seen[host] = true
				subs = append(subs, host)
			}
		}
	}
	return subs
}

// extractLiveHosts parses dnsx output lines for resolved hostnames.
// dnsx -resp output format: "sub.example.com [1.2.3.4]"
// We extract the hostname part (before the space or bracket).
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
			// Extract hostname: everything before first space or '['
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

// portRe matches port lines like "80/tcp open http" or "443/tcp open ssl/http"
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
			// masscan JSON: {"ip": "1.2.3.4", "ports": [{"port": 80, ...}]}
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

// extractWAF scans nmap output for http-waf-detect NSE results.
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
		// Also check for simpler WAF mention
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

// extractLiveURLs parses httpx output lines for URLs with scheme.
// httpx -status-code output format: "https://example.com [200]"
func extractLiveURLs(result ReconResult) []string {
	var urls []string
	seen := map[string]bool{}
	for _, tr := range result.Results {
		if tr.Tool != "httpx" {
			continue
		}
		for _, line := range strings.Split(tr.Output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if m := urlRe.FindString(line); m != "" {
				if !seen[m] {
					seen[m] = true
					urls = append(urls, m)
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
			if m := urlRe.FindString(line); m != "" {
				if !seen[m] {
					seen[m] = true
					urls = append(urls, m)
				}
			}
		}
	}
	return urls
}

// ensureToolQueued adds a tool to available if not already present.
// Used for auto-queuing tlsx when port 443/8443 is found.
func ensureToolQueued(name string, available []ToolSpec, registry []ToolSpec) []ToolSpec {
	for _, spec := range available {
		if spec.Name == name {
			return available // already present
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
// Safe to call multiple times — skips if "combined" entry already exists.
func buildCombined(result *ReconResult) {
	// Guard: don't add a second combined entry
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
	// Prepend combined entry
	if b.Len() > 0 {
		combined := ToolResult{Tool: "combined", Output: b.String()}
		result.Results = append([]ToolResult{combined}, result.Results...)
	}
}
