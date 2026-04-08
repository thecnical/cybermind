package hunt

import (
	"fmt"
	"strings"
)

// huntRegistry — full arsenal, 6 phases, no skipping.
// Every tool runs exhaustively. Primary → fallbacks → next tool.
// New tools added: waymore, gospider, paramspider, arjun, xsstrike, gf, uro
var huntRegistry = []HuntToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 1 — URL COLLECTION
	// Goal: collect EVERY historical URL from ALL archives before active testing
	// Pipeline: waymore → gau → waybackurls → deduplicate with uro
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "waymore",
		Phase:       1,
		Timeout:     900,
		DomainOnly:  true,
		InstallHint: "go install github.com/xnl-h4ck3r/waymore@latest",
		// Power: AlienVault OTX + CommonCrawl + Wayback + URLScan — best coverage
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"-i", target,
				"-mode", "U",          // URLs only
				"-oU", "/tmp/cybermind_waymore.txt",
				"-t", "50",            // 50 threads
				"-p", "wayback,otx,commoncrawl,urlscan",
				"-xrel",               // exclude relative URLs
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-i", target, "-mode", "U", "-oU", "/tmp/cybermind_waymore.txt"}
			},
		},
	},
	{
		Name:        "gau",
		Phase:       1,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"--subs",
				"--threads", "50",
				"--blacklist", "png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,pdf",
				"--providers", "wayback,otx,commoncrawl,urlscan",
				"--retries", "3",
				"--o", "/tmp/cybermind_gau.txt",
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"--subs", "--threads", "20", "--o", "/tmp/cybermind_gau.txt", target}
			},
		},
	},
	{
		Name:        "waybackurls",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2 — DEEP CRAWL
	// Goal: discover every JS endpoint, form, API path, hidden link
	// Pipeline: gospider (JS headless) → katana (structured crawl)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "gospider",
		Phase:       2,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/jaeles-project/gospider@latest",
		// Power: JS-aware, headless, infinite depth, 1000 threads
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-s", u,
				"-d", "10",        // depth 10
				"-t", "200",       // 200 threads
				"-c", "5",         // 5 concurrent
				"--js",            // parse JS files
				"--sitemap",       // parse sitemap
				"--robots",        // parse robots.txt
				"-o", "/tmp/cybermind_gospider/",
				"--no-redirect",
			}
			if len(ctx.LiveURLs) > 1 {
				// Multiple live URLs — use list mode
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-S", f,
						"-d", "10", "-t", "200", "-c", "5",
						"--js", "--sitemap", "--robots",
						"-o", "/tmp/cybermind_gospider/",
					}
				}
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-s", u, "-d", "5", "-t", "100", "--js", "-o", "/tmp/cybermind_gospider/"}
			},
		},
	},
	{
		Name:        "katana",
		Phase:       2,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-list", f,
						"-d", "10", "-c", "500",
						"-jc", "-kf", "all", "-aff",
						"-no-color", "-silent",
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
				"-d", "10", "-c", "500",
				"-jc", "-kf", "all", "-aff",
				"-no-color", "-silent",
				"-o", "/tmp/cybermind_katana_hunt.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "-d", "5", "-c", "200", "-jc", "-silent"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — PARAMETER DISCOVERY
	// Goal: find EVERY hidden GET/POST param — IDOR, SSRF, LFI, XSS, SQLi surface
	// Pipeline: paramspider (JS/HTML miner) → arjun (brute) → x8 (recursive fuzz)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "paramspider",
		Phase:       3,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider && cd /opt/paramspider && pip3 install -r requirements.txt && sudo ln -sf /opt/paramspider/paramspider.py /usr/local/bin/paramspider && sudo chmod +x /usr/local/bin/paramspider",
		// Power: mines JS, HTML, robots.txt for params — no active probing
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"--domain", target,
				"--level", "high",
				"--quiet",
				"--output", "/tmp/cybermind_paramspider.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"--domain", target, "--quiet"}
			},
		},
	},
	{
		Name:        "arjun",
		Phase:       3,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "pip3 install arjun",
		// Power: brute-force hidden params with massive wordlist
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-u", u,
				"-t", "100",       // 100 threads
				"-oJ", "/tmp/cybermind_arjun.json",
				"--stable",        // stable mode for accuracy
			}
			if ctx.WAFDetected {
				args = append(args, "--stable", "-d", "5")
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "-t", "50", "--stable"}
			},
		},
	},
	{
		Name:        "x8",
		Phase:       3,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "Download binary from https://github.com/Sh1Yo/x8/releases/latest — sudo cp x8 /usr/local/bin/ && sudo chmod +x /usr/local/bin/x8",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-u", u,
				"--level", "high",
				"--threads", "100",
				"--output", "/tmp/cybermind_x8.txt",
				"-q",
			}
			if ctx.WAFDetected {
				args = append(args, "--delay", "500")
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "--level", "medium", "--threads", "50", "-q"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 4 — XSS HUNTING
	// Goal: find every XSS — reflected, DOM, stored — with WAF bypass
	// Pipeline: xsstrike (AI WAF bypass) → dalfox (payload mutation)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "xsstrike",
		Phase:       4,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/s0md3v/XSStrike /opt/xsstrike && cd /opt/xsstrike && pip3 install -r requirements.txt && sudo tee /usr/local/bin/xsstrike > /dev/null << 'EOF'\n#!/bin/bash\npython3 /opt/xsstrike/xsstrike.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/xsstrike",
		// Power: AI-powered WAF bypass, fuzzing, DOM XSS detection
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"-u", u,
				"--fuzzer",        // enable fuzzer
				"--blind",         // blind XSS
				"--skip",          // skip confirmation
				"--threads", "10",
			}
			if ctx.WAFDetected {
				args = append(args, "--waf")
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "--skip", "--threads", "5"}
			},
		},
	},
	{
		Name:        "dalfox",
		Phase:       4,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "go install github.com/hahwul/dalfox/v2@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			scanURLs := dedup(append(ctx.LiveURLs, ctx.CrawledURLs...))
			for _, u := range ctx.HistoricalURLs {
				if strings.Contains(u, "=") {
					scanURLs = append(scanURLs, u)
				}
			}
			scanURLs = dedup(scanURLs)

			if len(scanURLs) > 0 {
				f := writeTempList(scanURLs)
				if f != "" {
					args := []string{
						"file", f,
						"--silence", "--no-color",
						"--follow-redirects",
						"--waf-bypass",
						"--trigger", "alert(1)",
						"--output", "/tmp/cybermind_dalfox.txt",
					}
					if ctx.WAFDetected {
						args = append(args, "--delay", "1000", "--timeout", "30")
					}
					return args
				}
			}
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"url", u, "--silence", "--no-color", "--waf-bypass", "--follow-redirects"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"url", u, "--silence", "--no-color"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 5 — DEEP VULNERABILITY SCAN
	// Goal: CVEs, RCE, LFI, SSRF, misconfigs — full template coverage
	// Pipeline: gf (pattern filter) → uro (dedup) → nuclei (scan)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "gf",
		Phase:       5,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf",
		// Power: filter URLs by vulnerability pattern (xss, sqli, ssrf, lfi, rce, redirect)
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// gf filters stdin — we pipe all URLs through it
			// Run multiple patterns and save to files
			allURLs := dedup(append(append(ctx.AllURLs, ctx.LiveURLs...), ctx.CrawledURLs...))
			if len(allURLs) == 0 {
				return []string{"xss"} // minimal fallback
			}
			f := writeTempList(allURLs)
			if f == "" {
				return []string{"xss"}
			}
			// Run gf for multiple patterns
			return []string{
				"xss",
				// Note: gf reads from stdin, so we use bash -c in the engine
				// This BuildArgs returns the pattern; engine handles piping
			}
		},
	},
	{
		Name:        "nuclei",
		Phase:       5,
		Timeout:     7200,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-silent", "-no-color", "-stats", "-progress",
				"-c", "1000", "-rl", "200", "-bs", "50",
				"-timeout", "10", "-retries", "3",
				"-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)",
				"-H", "X-Originating-IP: 127.0.0.1",
				"-o", "/tmp/cybermind_nuclei_hunt.txt",
			}
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos", "-severity", "critical,high,medium", "-rl", "50")
			} else {
				args = append(args, "-severity", "critical,high,medium,low,info",
					"-tags", "cve,xss,sqli,ssrf,lfi,rce,xxe,idor,misconfig,exposure,takeover,oast,ssti,redirect")
			}
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
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-u", target, "-severity", "critical,high", "-silent", "-no-color", "-c", "200"}
			},
			func(target string, ctx *HuntContext) []string {
				return []string{"-u", target, "-t", "cves/", "-silent", "-no-color"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 6 — NETWORK VULNERABILITY SCRIPTS
	// Goal: network-level CVEs — Heartbleed, SMB vulns, SSL issues, auth bypass
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "nmap",
		Phase:       6,
		Timeout:     3600,
		DomainOnly:  false,
		InstallHint: "sudo apt install nmap",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-sV",
				"--script", "vuln,exploit,auth,http-vuln*,ssl-heartbleed,ssl-enum-ciphers,smb-vuln*,dns-zone-transfer,ftp-anon,smtp-vuln*",
				"--script-args", fmt.Sprintf("unsafe=1,smbsecuritymode=1,vulns.showall"),
				"-Pn", "--open", "-T4",
				"--version-intensity", "9",
				"-oA", "/tmp/cybermind_nmap_hunt",
			}
			if len(ctx.OpenPorts) > 0 {
				ports := make([]string, len(ctx.OpenPorts))
				for i, p := range ctx.OpenPorts {
					ports[i] = fmt.Sprintf("%d", p)
				}
				args = append(args, "-p", strings.Join(ports, ","))
			} else {
				args = append(args, "--top-ports", "5000")
			}
			args = append(args, target)
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-sV", "--script", "vuln", "-Pn", "--open", "--top-ports", "1000", target}
			},
		},
	},
}
