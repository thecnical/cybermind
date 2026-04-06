package hunt

import (
	"fmt"
	"strings"
)

// huntRegistry defines all hunt tools across 6 phases.
// All tools are Go/Rust/apt — no Python dependencies.
var huntRegistry = []HuntToolSpec{

	// ── Phase 1: URL Collection ──────────────────────────────────────────────
	// Collect all historical + archived URLs before active testing
	{
		Name:        "gau",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// gau reads domain from stdin via pipe, but also accepts --subs flag
			return []string{"--subs", "--threads", "5", target}
		},
	},
	{
		Name:        "waybackurls",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// waybackurls reads from stdin — we pass target as arg via echo pipe
			// Since we can't pipe in exec.Command, we use the direct arg form
			return []string{target}
		},
	},

	// ── Phase 2: Deep Crawl ──────────────────────────────────────────────────
	// katana deep crawl — discovers JS endpoints, forms, API paths
	{
		Name:        "katana-hunt",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Use live URLs from recon if available, else root target
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{"-u", u, "-silent", "-depth", "5", "-jc", "-kf", "all", "-aff"}
			// If multiple live URLs, write to temp file
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{"-list", f, "-silent", "-depth", "5", "-jc", "-kf", "all", "-aff"}
				}
			}
			return args
		},
	},

	// ── Phase 3: Parameter Discovery ────────────────────────────────────────
	// x8 — finds hidden GET/POST parameters that could be vulnerable
	{
		Name:        "x8",
		Phase:       3,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "cargo install x8  (requires: sudo apt install cargo)",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-u", u, "--output-format", "url", "-q"}
		},
	},

	// ── Phase 4: XSS Hunting ────────────────────────────────────────────────
	// dalfox — automated XSS scanner with DOM verification
	{
		Name:        "dalfox",
		Phase:       4,
		Timeout:     180,
		DomainOnly:  true,
		InstallHint: "go install github.com/hahwul/dalfox/v2@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// If we have historical URLs, scan them all via pipe mode
			allURLs := append(ctx.LiveURLs, ctx.CrawledURLs...)
			// Deduplicate
			seen := map[string]bool{}
			var unique []string
			for _, u := range allURLs {
				if !seen[u] {
					seen[u] = true
					unique = append(unique, u)
				}
			}
			if len(unique) > 0 {
				f := writeTempList(unique)
				if f != "" {
					args := []string{"file", f, "--silence", "--no-color", "--output-all"}
					if ctx.WAFDetected {
						args = append(args, "--delay", "500")
					}
					return args
				}
			}
			// Fallback: scan root target
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{"url", u, "--silence", "--no-color"}
			if ctx.WAFDetected {
				args = append(args, "--delay", "500")
			}
			return args
		},
	},

	// ── Phase 5: Deep Vulnerability Scan ────────────────────────────────────
	// nuclei with ALL severity levels + specific vuln tags
	{
		Name:        "nuclei-hunt",
		Phase:       5,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{"-silent", "-no-color", "-severity", "critical,high,medium,low"}

			// WAF-adaptive: exclude aggressive templates
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos")
			}

			// Use crawled URLs for deeper coverage
			allURLs := ctx.CrawledURLs
			if len(allURLs) == 0 {
				allURLs = ctx.LiveURLs
			}
			if len(allURLs) > 0 {
				f := writeTempList(allURLs)
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
	// nmap --script vuln — runs all vulnerability detection NSE scripts
	{
		Name:        "nmap-vuln",
		Phase:       6,
		Timeout:     180,
		DomainOnly:  false,
		InstallHint: "sudo apt install nmap",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{"-sV", "--script", "vuln", "-Pn", "--open"}
			// If we know open ports, scan only those (faster)
			if len(ctx.OpenPorts) > 0 {
				ports := make([]string, len(ctx.OpenPorts))
				for i, p := range ctx.OpenPorts {
					ports[i] = fmt.Sprintf("%d", p)
				}
				args = append(args, "-p", strings.Join(ports, ","))
			} else {
				args = append(args, "--top-ports", "1000")
			}
			args = append(args, target)
			return args
		},
	},
}
