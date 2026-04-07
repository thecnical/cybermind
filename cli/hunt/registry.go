package hunt

import (
	"fmt"
	"strings"
)

// huntRegistry defines all hunt tools across 6 phases.
// reconftw-inspired: maximum coverage, no shortcuts, chahe kitna bhi time lage.
// Each tool uses its most powerful command configuration.
var huntRegistry = []HuntToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 1 — URL COLLECTION
	// Goal: collect every historical URL from all archives before active testing
	// These URLs feed into dalfox (XSS), x8 (params), nuclei (vulns)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "gau",
		Phase:       1,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		// Power command: all sources including subs, 50 threads, blacklist static assets
		// Sources: Wayback Machine, AlienVault OTX, CommonCrawl, URLScan
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"--subs",                                                    // include subdomains
				"--threads", "50",                                           // 50 parallel threads
				"--blacklist", "png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,pdf", // skip static
				"--providers", "wayback,otx,commoncrawl,urlscan",           // all providers
				"--retries", "3",
				"--verbose",
				"--o", "/tmp/cybermind_gau.txt",
				target,
			}
		},
	},
	{
		Name:        "waybackurls",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		// Power command: wildcard subdomain coverage
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// waybackurls takes domain on stdin — we pass it as arg
			return []string{target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2 — DEEP CRAWL
	// Goal: discover every JS endpoint, form, API path, hidden link
	// Uses recon LiveURLs for maximum accuracy
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "katana",
		Phase:       2,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		// Power command: depth 10, 500 concurrency, JS crawl, form fill, headless mode
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Use all live URLs from recon for maximum coverage
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-list", f,
						"-d", "10",   // depth 10 — maximum
						"-c", "500",  // 500 concurrency
						"-jc",        // parse JS files
						"-kf", "all", // known files (robots.txt, sitemap.xml, etc.)
						"-aff",       // automatic form fill
						"-no-color",
						"-silent",
						"-o", "/tmp/cybermind_katana_hunt.txt",
					}
				}
			}
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u,
				"-d", "10",
				"-c", "500",
				"-jc", "-kf", "all", "-aff",
				"-no-color",
				"-silent",
				"-o", "/tmp/cybermind_katana_hunt.txt",
			}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — PARAMETER DISCOVERY
	// Goal: find every hidden GET/POST parameter — IDOR, SSRF, LFI, XSS, SQLi surface
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "x8",
		Phase:       3,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "cargo install x8  (requires: sudo apt install cargo)",
		// Power command: insane level, 100 threads, grep sensitive params
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Use best available URL
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-u", u,
				"--level", "high", // high level param discovery
				"--threads", "100",
				"--output", "/tmp/cybermind_x8.txt",
				"-q", // quiet
			}
			// WAF-adaptive: add delay if WAF detected
			if ctx.WAFDetected {
				args = append(args, "--delay", "500")
			}
			return args
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 4 — XSS HUNTING
	// Goal: find every XSS — reflected, DOM, stored — with WAF bypass
	// Scans ALL collected URLs from phases 1+2+3
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "dalfox",
		Phase:       4,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "go install github.com/hahwul/dalfox/v2/cmd/dalfox@latest",
		// Power command: WAF bypass, 200 threads, custom trigger, param ID, POC generation
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Build comprehensive URL list: LiveURLs + CrawledURLs (best for XSS)
			scanURLs := dedup(append(ctx.LiveURLs, ctx.CrawledURLs...))
			// Also add historical URLs with params
			for _, u := range ctx.HistoricalURLs {
				if strings.Contains(u, "=") { // only URLs with params
					scanURLs = append(scanURLs, u)
				}
			}
			scanURLs = dedup(scanURLs)

			if len(scanURLs) > 0 {
				f := writeTempList(scanURLs)
				if f != "" {
					args := []string{
						"file", f,
						"--silence",
						"--no-color",
						"--follow-redirects",
						"--waf-bypass",
						"--trigger", "alert(1)",
						"--output", "/tmp/cybermind_dalfox.txt",
					}
					if ctx.WAFDetected {
						args = append(args, "--delay", "1000", "--timeout", "30")
					} else {
						args = append(args, "--timeout", "15")
					}
					return args
				}
			}
			// Fallback: scan root target
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"url", u,
				"--silence",
				"--no-color",
				"--follow-redirects",
				"--waf-bypass",
				"--output", "/tmp/cybermind_dalfox.txt",
			}
			if ctx.WAFDetected {
				args = append(args, "--delay", "1000")
			}
			return args
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 5 — DEEP VULNERABILITY SCAN
	// Goal: CVEs, RCE, LFI, SSRF, misconfigs, exposures — full template coverage
	// Uses CrawledURLs > LiveURLs > target (deepest coverage first)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "nuclei",
		Phase:       5,
		Timeout:     7200,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		// Power command: 1000 concurrency, bulk 50, evasion mode, all severities, all tags
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-silent",
				"-no-color",
				"-stats",
				"-progress",
				"-c", "1000",   // 1000 concurrency
				"-rl", "200",   // rate limit 200 req/s
				"-bs", "50",    // bulk size 50
				"-timeout", "10",
				"-retries", "3",
				"-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)",
				"-H", "X-Originating-IP: 127.0.0.1",
				"-o", "/tmp/cybermind_nuclei_hunt.txt",
			}
			// WAF-adaptive
			if ctx.WAFDetected {
				args = append(args,
					"-etags", "fuzzing,dos",
					"-severity", "critical,high,medium",
					"-rl", "50", // slower for WAF
				)
			} else {
				args = append(args,
					"-severity", "critical,high,medium,low,info",
					"-tags", "cve,xss,sqli,ssrf,lfi,rce,xxe,idor,misconfig,exposure,takeover,oast,ssti,redirect",
				)
			}
			// Best URL source: crawled > live > target
			scanURLs := ctx.CrawledURLs
			if len(scanURLs) == 0 {
				scanURLs = ctx.LiveURLs
			}
			if len(scanURLs) > 0 {
				f := writeTempList(scanURLs)
				if f != "" {
					args = append(args, "-l", f)
					return args
				}
			}
			args = append(args, "-u", target)
			return args
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 6 — NETWORK VULNERABILITY SCRIPTS
	// Goal: network-level CVEs — Heartbleed, SMB vulns, SSL issues, auth bypass
	// Adaptive: uses known open ports from recon (much faster)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "nmap",
		Phase:       6,
		Timeout:     3600,
		DomainOnly:  false, // works on both domain and IP
		InstallHint: "sudo apt install nmap",
		// Power command: vuln+exploit scripts, unsafe mode, all ports, SSL checks
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-sV",
				"--script", "vuln,exploit,auth,http-vuln*,ssl-heartbleed,ssl-enum-ciphers,smb-vuln*,dns-zone-transfer,ftp-anon,smtp-vuln*",
				"--script-args", fmt.Sprintf("unsafe=1,smbsecuritymode=1,vulns.showall"),
				"-Pn",
				"--open",
				"-T4",
				"--version-intensity", "9",
				"-oA", "/tmp/cybermind_nmap_hunt",
			}
			// Adaptive: use known open ports from recon (much faster than full scan)
			if len(ctx.OpenPorts) > 0 {
				ports := make([]string, len(ctx.OpenPorts))
				for i, p := range ctx.OpenPorts {
					ports[i] = fmt.Sprintf("%d", p)
				}
				args = append(args, "-p", strings.Join(ports, ","))
			} else {
				// No port info — scan top 5000 ports
				args = append(args, "--top-ports", "5000")
			}
			args = append(args, target)
			return args
		},
	},
}
