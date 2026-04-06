package hunt

import (
	"fmt"
	"strings"
)

// huntRegistry defines all hunt tools across 6 phases.
// All tools are Go/Rust/apt — no Python dependencies.
// Each BuildArgs uses HuntContext for intelligent chaining.
var huntRegistry = []HuntToolSpec{

	// ── Phase 1: URL Collection ──────────────────────────────────────────────
	// Collect all historical + archived URLs BEFORE active testing.
	// These feed into dalfox (XSS) and nuclei (vuln scan) in later phases.
	{
		Name:        "gau",
		Phase:       1,
		Timeout:     90,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// gau: fetch URLs from Wayback Machine, AlienVault OTX, CommonCrawl, URLScan
			return []string{"--subs", "--threads", "5", "--blacklist", "png,jpg,gif,svg,ico,css,woff", target}
		},
	},
	{
		Name:        "waybackurls",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// waybackurls: Wayback Machine archived URLs
			return []string{target}
		},
	},

	// ── Phase 2: Deep Crawl ──────────────────────────────────────────────────
	// katana crawls live URLs from recon (or root target in manual mode).
	// Discovers JS endpoints, forms, API paths, hidden links.
	// Output feeds into x8 (params), dalfox (XSS), nuclei (vulns).
	{
		Name:        "katana",
		Phase:       2,
		Timeout:     180,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Use live URLs from recon if available — more accurate than root target
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-list", f,
						"-silent", "-depth", "5",
						"-jc",        // parse JS files
						"-kf", "all", // known files
						"-aff",       // automatic form fill
						"-no-color",
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
				"-silent", "-depth", "5",
				"-jc", "-kf", "all", "-aff",
				"-no-color",
			}
		},
	},

	// ── Phase 3: Parameter Discovery ────────────────────────────────────────
	// x8 discovers hidden GET/POST parameters that could be vulnerable to
	// IDOR, SSRF, LFI, open redirect, XSS, SQLi.
	// Uses live URLs from recon context.
	{
		Name:        "x8",
		Phase:       3,
		Timeout:     180,
		DomainOnly:  true,
		InstallHint: "cargo install x8  (requires: sudo apt install cargo)",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Use first live URL for parameter discovery
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{"-u", u, "-q"}
			// WAF-adaptive: add delay if WAF detected
			if ctx.WAFDetected {
				args = append(args, "--delay", "500")
			}
			return args
		},
	},

	// ── Phase 4: XSS Hunting ────────────────────────────────────────────────
	// dalfox is the most powerful XSS scanner — automated payload injection
	// with DOM verification. Scans ALL collected URLs from phases 1+2.
	// Cascade: ffuf-xss → dalfox (dalfox is primary, no cascade needed here)
	{
		Name:        "dalfox",
		Phase:       4,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/hahwul/dalfox/v2/cmd/dalfox@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Build URL list: LiveURLs + CrawledURLs (most valuable for XSS)
			// Historical URLs are too many — use only confirmed live ones
			scanURLs := dedup(append(ctx.LiveURLs, ctx.CrawledURLs...))

			if len(scanURLs) > 0 {
				f := writeTempList(scanURLs)
				if f != "" {
					args := []string{"file", f, "--silence", "--no-color", "--follow-redirects"}
					if ctx.WAFDetected {
						// WAF detected: slow down to avoid blocks
						args = append(args, "--delay", "1000", "--timeout", "30")
					}
					return args
				}
			}
			// Fallback: scan root target
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{"url", u, "--silence", "--no-color", "--follow-redirects"}
			if ctx.WAFDetected {
				args = append(args, "--delay", "1000")
			}
			return args
		},
	},

	// ── Phase 5: Deep Vulnerability Scan ────────────────────────────────────
	// nuclei with ALL severity levels + full template coverage.
	// Uses CrawledURLs (deepest coverage) > LiveURLs > root target.
	// WAF-adaptive: excludes fuzzing/dos templates if WAF detected.
	{
		Name:        "nuclei",
		Phase:       5,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-silent", "-no-color",
				"-severity", "critical,high,medium,low",
				"-stats",
			}
			// WAF-adaptive: exclude aggressive templates
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos")
			}
			// Use best available URL list (priority: crawled > live > target)
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

	// ── Phase 6: Network Vulnerability Scripts ───────────────────────────────
	// nmap --script vuln runs all NSE vulnerability detection scripts.
	// Adaptive: uses known open ports from recon (much faster than full scan).
	// Works on both domain and IP targets.
	{
		Name:        "nmap",
		Phase:       6,
		Timeout:     300,
		DomainOnly:  false,
		InstallHint: "sudo apt install nmap",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{"-sV", "--script", "vuln", "-Pn", "--open"}
			// Adaptive: if we know open ports from recon, scan only those
			if len(ctx.OpenPorts) > 0 {
				ports := make([]string, len(ctx.OpenPorts))
				for i, p := range ctx.OpenPorts {
					ports[i] = fmt.Sprintf("%d", p)
				}
				args = append(args, "-p", strings.Join(ports, ","))
			} else {
				// No port info — scan top 1000
				args = append(args, "--top-ports", "1000")
			}
			args = append(args, target)
			return args
		},
	},
}
