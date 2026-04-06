package recon

import (
	"os"
	"strings"
)

// toolRegistry defines all 16 supported recon tools across 6 phases.
var toolRegistry = []ToolSpec{
	// ── Phase 1: Passive OSINT ──────────────────────────────────────────────
	{
		Name:        "whois",
		Phase:       1,
		Timeout:     30,
		InstallHint: "sudo apt install whois",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{target}
		},
	},
	{
		Name:        "theHarvester",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "sudo apt install theharvester",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target, "-b", "google,bing,yahoo,duckduckgo", "-l", "200"}
		},
	},
	{
		Name:        "dig",
		Phase:       1,
		Timeout:     15,
		InstallHint: "sudo apt install dnsutils",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"+short", "ANY", target}
		},
	},

	// ── Phase 2: Subdomain Enumeration ──────────────────────────────────────
	{
		Name:        "subfinder",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target, "-silent"}
		},
	},
	{
		Name:        "amass",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "sudo apt install amass",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"enum", "-passive", "-d", target}
		},
	},
	{
		Name:        "dnsx",
		Phase:       2,
		Timeout:     30,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				return []string{"-l", f, "-silent", "-a", "-resp"}
			}
			return []string{"-d", target, "-silent", "-a", "-resp"}
		},
	},

	// ── Phase 3: Port Scanning ───────────────────────────────────────────────
	{
		Name:         "rustscan",
		Phase:        3,
		Timeout:      60,
		CascadeGroup: "portscan",
		InstallHint:  "sudo apt install rustscan",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-a", target, "--ulimit", "5000", "--", "-sV", "-sC"}
		},
	},
	{
		Name:         "naabu",
		Phase:        3,
		Timeout:      60,
		CascadeGroup: "portscan",
		InstallHint:  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-host", target, "-silent", "-top-ports", "1000"}
		},
	},
	{
		Name:         "nmap",
		Phase:        3,
		Timeout:      120,
		CascadeGroup: "portscan",
		InstallHint:  "sudo apt install nmap",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-sV", "-T4", "--open", "-Pn", "--top-ports", "1000",
				"--script", "http-waf-detect", target}
		},
	},
	{
		Name:        "masscan",
		Phase:       3,
		Timeout:     60,
		InstallHint: "sudo apt install masscan",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-p", "1-65535", "--rate", "1000", target}
		},
	},

	// ── Phase 4: HTTP Probing & Fingerprinting ───────────────────────────────
	{
		Name:        "httpx",
		Phase:       4,
		Timeout:     30,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.LiveHosts) > 0 {
				f := writeTempList(ctx.LiveHosts)
				return []string{"-l", f, "-silent", "-status-code", "-title", "-tech-detect"}
			}
			return []string{"-u", target, "-silent", "-status-code", "-title", "-tech-detect"}
		},
	},
	{
		Name:        "whatweb",
		Phase:       4,
		Timeout:     30,
		DomainOnly:  true,
		InstallHint: "sudo apt install whatweb",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"--color=never", "-a", "3", target}
		},
	},
	{
		Name:        "tlsx",
		Phase:       4,
		Timeout:     20,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-u", target, "-silent", "-san", "-cn", "-so", "-resp"}
		},
	},

	// ── Phase 5: Directory & Endpoint Discovery ──────────────────────────────
	{
		Name:         "ffuf",
		Phase:        5,
		Timeout:      90,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install ffuf",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{"-u", baseURL + "/FUZZ", "-w", wl, "-mc", "200,301,302,403", "-silent"}
			if ctx.WAFDetected {
				args = append(args, "-rate", "10")
			}
			return args
		},
	},
	{
		Name:         "feroxbuster",
		Phase:        5,
		Timeout:      90,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install feroxbuster",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{"-u", baseURL, "-w", wl, "--silent", "--no-state"}
			if ctx.WAFDetected {
				args = append(args, "--rate-limit", "10")
			}
			return args
		},
	},
	{
		Name:         "gobuster",
		Phase:        5,
		Timeout:      60,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install gobuster",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{"dir", "-u", baseURL, "-w", wl, "-q", "--no-error", "-t", "20"}
			if ctx.WAFDetected {
				args = append(args, "--delay", "100ms")
			}
			return args
		},
	},

	// ── Phase 6: Vulnerability Scanning ─────────────────────────────────────
	{
		Name:        "nuclei",
		Phase:       6,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			args := []string{"-silent", "-no-color"}
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos")
			} else {
				args = append(args, "-severity", "critical,high,medium")
			}
			if len(ctx.CrawledURLs) > 0 {
				f := writeTempList(ctx.CrawledURLs)
				args = append(args, "-l", f)
			} else if len(ctx.LiveURLs) > 0 {
				f := writeTempList(ctx.LiveURLs)
				args = append(args, "-l", f)
			} else {
				args = append(args, "-u", target)
			}
			return args
		},
	},
	{
		Name:        "nikto",
		Phase:       6,
		Timeout:     90,
		DomainOnly:  true,
		InstallHint: "sudo apt install nikto",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			h := target
			if len(ctx.LiveURLs) > 0 {
				h = ctx.LiveURLs[0]
			}
			return []string{"-h", h, "-nointeractive", "-Format", "txt"}
		},
	},
	{
		Name:        "katana",
		Phase:       6,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-u", u, "-silent", "-depth", "3", "-jc"}
		},
	},
}

// ToolNames returns all tool names in the registry (used for --tools validation).
func ToolNames() []string {
	names := make([]string, len(toolRegistry))
	for i, spec := range toolRegistry {
		names[i] = spec.Name
	}
	return names
}

// writeTempList writes a slice of strings to a temp file and returns the path.
// Callers accept that temp files persist for the process lifetime.
func writeTempList(items []string) string {
	f, err := os.CreateTemp("", "cybermind-list-*.txt")
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, item := range items {
		f.WriteString(item + "\n")
	}
	return f.Name()
}
