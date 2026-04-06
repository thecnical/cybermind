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
			return []string{"--subs", "--threads", "5", target}
		},
	},
	{
		// waybackurls reads domain from stdin — we use sh -c "echo domain | waybackurls"
		// but since exec.Command can't pipe, we use the binary's direct positional arg support
		// waybackurls v2+ accepts domain as positional arg: waybackurls example.com
		Name:        "waybackurls",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{target}
		},
	},

	// ── Phase 2: Deep Crawl ──────────────────────────────────────────────────
	// katana deep crawl — discovers JS endpoints, forms, API paths
	// Note: registry Name is "katana-hunt" but actual binary is "katana"
	// We override the binary lookup via the run() call using spec.Name mapped to "katana"
	{
		Name:        "katana",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// If multiple live URLs, write to temp file
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{"-list", f, "-silent", "-depth", "5", "-jc", "-kf", "all", "-aff"}
				}
			}
			return []string{"-u", u, "-silent", "-depth", "5", "-jc", "-kf", "all", "-aff"}
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
			// x8 flags: -u URL, -w wordlist (uses built-in if not specified), -q quiet
			return []string{"-u", u, "-q"}
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
			// Collect all URLs to scan
			allURLs := make([]string, 0)
			allURLs = append(allURLs, ctx.LiveURLs...)
			allURLs = append(allURLs, ctx.CrawledURLs...)
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
					// dalfox pipe mode: reads URLs from file
					args := []string{"pipe", "--silence", "--no-color", "-b", "https://hahwul.com/dalfox/"}
					if ctx.WAFDetected {
						args = append(args, "--delay", "500")
					}
					// Use file mode instead of pipe for reliability
					return []string{"file", f, "--silence", "--no-color"}
				}
			}
			// Fallback: scan root target URL
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
	// Uses "nuclei" binary but registered as separate hunt phase tool
	{
		Name:        "nuclei",
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
		Name:        "nmap",
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
