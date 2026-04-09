package recon

import (
	"fmt"
	"os"
	"strings"
)

// toolRegistry defines all recon tools across 6 phases.
// Each tool runs its most powerful command set — reconftw-inspired approach.
// Timeouts are generous: we want 100% tool coverage, not speed.
// Cascade groups: only first available tool in group runs (prevents redundancy).
var toolRegistry = []ToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 1 — PASSIVE OSINT
	// Goal: registration data, emails, DNS records, org intel — zero active probing
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "whois",
		Phase:       1,
		Timeout:     120,
		InstallHint: "sudo apt install whois",
		// Power command: verbose output for full ownership intel
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-v", target}
		},
		// Fallback 1: basic whois if -v fails
		// Fallback 2: ARIN-specific lookup
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{target}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-h", "whois.arin.net", target}
			},
		},
	},
	{
		Name:        "theHarvester",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install theharvester",
		// Power command: all sources, 5000 limit, DNS TLS for stealthy subdomain/email harvest
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-d", target,
				"-l", "5000",
				"-b", "google,bing,yahoo,duckduckgo,baidu,linkedin,pgp,hunter,securitytrails,shodan,otx,threatminer,urlscan",
				"-f", "/tmp/cybermind_harvest",
				"--dns-tls",
			}
		},
		// Fallback 1: fewer sources (some may be rate-limited)
		// Fallback 2: minimal — just google+bing
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-l", "2000", "-b", "google,bing,yahoo,duckduckgo,otx"}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-l", "500", "-b", "google,bing"}
			},
		},
	},
	{
		Name:        "dig",
		Phase:       1,
		Timeout:     60,
		InstallHint: "sudo apt install dnsutils",
		// Power command: full ANY trace + all record types
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"+nocmd", "+noall", "+answer", "+multiline", "ANY", target}
		},
		// Fallback 1: standard ANY query
		// Fallback 2: AXFR zone transfer attempt
		// Fallback 3: TXT records only (SPF/DMARC intel)
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"+short", "ANY", target}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"@8.8.8.8", target, "AXFR"}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"+short", "TXT", target}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2 — SUBDOMAIN ENUMERATION
	// Goal: maximum subdomain coverage — passive + active + brute + permutations
	// reconftw approach: subfinder (passive) → amass (brute+passive) → dnsx (resolve all)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "subfinder",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		// Power command: all passive sources, 500 threads
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-d", target,
				"-all",
				"-t", "500",
				"-timeout", "30",
				"-silent",
				"-o", "/tmp/cybermind_subfinder.txt",
			}
		},
		// Fallback 1: without -all flag (some sources may block)
		// Fallback 2: minimal — just basic passive
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-t", "200", "-silent"}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},
	{
		Name:        "amass",
		Phase:       2,
		Timeout:     900,
		DomainOnly:  true,
		InstallHint: "sudo apt install amass",
		// Power command: passive + active brute with top 5M wordlist, 100 netblocks
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Check if large wordlist exists for brute force
			bruteList := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(bruteList); err == nil {
				return []string{
					"enum",
					"-d", target,
					"-passive",
					"-brute",
					"-w", bruteList,
					"-maxnets", "100",
					"-timeout", "15",
					"-o", "/tmp/cybermind_amass.txt",
				}
			}
			// Fallback: passive only
			return []string{
				"enum",
				"-passive",
				"-d", target,
				"-timeout", "15",
				"-o", "/tmp/cybermind_amass.txt",
			}
		},
	},
	// reconftw — PHASE 2 PRIMARY TOOL — runs BEFORE subfinder/amass
	// reconftw is a meta-tool that internally runs 50+ tools across all phases:
	// passive enum, cert transparency, brute force, permutations, web probing,
	// vuln scanning, OSINT, JS analysis, parameter discovery, and more.
	//
	// CyberMind uses reconftw in FULL RECON mode (-r) with --deep for maximum coverage.
	// reconftw output is parsed to extract subdomains, live hosts, URLs, and vulns
	// which then feed into CyberMind's own Phase 3-6 tools for additional coverage.
	//
	// Install: git clone https://github.com/six2dez/reconftw.git /opt/reconftw
	//          cd /opt/reconftw && ./install.sh
	//          sudo tee /usr/local/bin/reconftw > /dev/null << 'EOF'
	//          #!/bin/bash
	//          cd /opt/reconftw && bash reconftw.sh "$@"
	//          EOF
	//          sudo chmod +x /usr/local/bin/reconftw
	{
		Name:        "reconftw",
		Phase:       2,
		Timeout:     14400, // 4 hours max — reconftw is thorough, we wait
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh && sudo tee /usr/local/bin/reconftw > /dev/null << 'EOF'\n#!/bin/bash\ncd /opt/reconftw && bash reconftw.sh \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/reconftw",
		// PRIMARY: Full recon mode with deep scanning + parallel execution
		// -r = full recon (subdomains + web probing + vuln checks, no active attacks)
		// --deep = enable deep scanning (more thorough, slower)
		// --parallel = run independent functions in parallel (faster)
		// -o = output directory for structured results
		BuildArgs: func(target string, ctx *ReconContext) []string {
			outDir := "/tmp/cybermind_reconftw_" + target
			return []string{
				"-d", target,
				"-r",          // full recon mode
				"--deep",      // deep scanning — no shortcuts
				"--parallel",  // parallel execution for speed
				"-o", outDir,  // structured output directory
			}
		},
		// Fallback 1: full recon without --deep (faster, still comprehensive)
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				return []string{
					"-d", target,
					"-r",
					"--parallel",
					"-o", outDir,
				}
			},
			// Fallback 2: subdomain-only mode (-s) — fastest, still very thorough
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				return []string{
					"-d", target,
					"-s",         // subdomain enumeration only
					"--parallel",
					"-o", outDir,
				}
			},
			// Fallback 3: passive only (-p) — no active probing, stealthy
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				return []string{
					"-d", target,
					"-p",         // passive only
					"-o", outDir,
				}
			},
		},
	},

	{
		Name:        "dnsx",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		// Power command: resolve all subdomains, all record types, wildcard filter, 500 threads
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{
						"-l", f,
						"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-soa", // all record types
						"-resp",
						"-resp-only",
						"-wildcard-filter",
						"-t", "500",
						"-silent",
						"-o", "/tmp/cybermind_dnsx.txt",
					}
				}
			}
			return []string{
				"-d", target,
				"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt",
				"-resp",
				"-wildcard-filter",
				"-t", "200",
				"-silent",
			}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — PORT SCANNING
	// Goal: find every open port, service version, OS, WAF — full coverage
	// Cascade: rustscan (fastest) → naabu (fast+nmap) → nmap (deepest)
	// masscan runs independently (no cascade) for ultra-fast initial sweep
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:         "rustscan",
		Phase:        3,
		Timeout:      600,
		CascadeGroup: "portscan",
		InstallHint:  "sudo apt install rustscan",
		// Power command: all 65535 ports, 10k ulimit, 2000 batch, pipe to nmap for deep service scan
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-a", target,
				"--ulimit", "10000",
				"-b", "2000",
				"-t", "50",
				"--",
				// nmap args after --
				"-sS", "-sV", "-sC",
				"-T4", "--open", "-Pn",
				"--script", "http-waf-detect,http-headers,banner,ssl-cert,http-title",
				"-O", "--osscan-guess",
				"--version-intensity", "9",
			}
		},
	},
	{
		Name:         "naabu",
		Phase:        3,
		Timeout:      600,
		CascadeGroup: "portscan",
		InstallHint:  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		// Power command: full port range, 1000 threads, nmap integration for service detection
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-host", target,
				"-p", "-",    // all 65535 ports
				"-t", "1000", // 1000 threads
				"-rate", "10000",
				"-retries", "3",
				"-silent",
				"-nmap-cli", "nmap -sV -sC -T4 --open --script http-waf-detect,banner,ssl-cert",
				"-o", "/tmp/cybermind_naabu.txt",
			}
		},
	},
	{
		Name:         "nmap",
		Phase:        3,
		Timeout:      1800,
		CascadeGroup: "portscan",
		InstallHint:  "sudo apt install nmap",
		// Power command: full port SYN scan, all scripts, OS detection, version intensity max
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-sS", "-sV", "-sC",
				"-T4", "--open", "-Pn",
				"-p-",                 // all 65535 ports
				"--min-rate", "10000", // fast scan
				"--script", "http-waf-detect,http-headers,banner,ssl-cert,http-title,http-methods,http-auth-finder,dns-zone-transfer,smtp-commands,ftp-anon,ssh-auth-methods",
				"-O", "--osscan-guess",
				"--version-intensity", "9",
				"--script-args", "http.useragent='Mozilla/5.0 (compatible; Googlebot/2.1)'",
				"-oA", "/tmp/cybermind_nmap",
				target,
			}
		},
	},
	{
		Name:        "masscan",
		Phase:       3,
		Timeout:     300,
		InstallHint: "sudo apt install masscan",
		// Power command: 1M packets/sec, all ports, banner grabbing — runs independently
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				target,
				"-p", "1-65535",
				"--rate", "100000", // 100k pps (safe default, not 1M which needs root+adapter)
				"--banners",
				"--wait", "3",
				"-oJ", "/tmp/cybermind_masscan.json",
			}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 4 — HTTP FINGERPRINTING
	// Goal: live URL discovery, tech stack, TLS certs, CSP, vhosts, screenshots
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "httpx",
		Phase:       4,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
		// Power command: 500 threads, full fingerprint — tech, TLS, CSP, title, status, IP, CNAME
		BuildArgs: func(target string, ctx *ReconContext) []string {
			var input []string
			if len(ctx.LiveHosts) > 0 {
				f := writeTempList(ctx.LiveHosts)
				if f != "" {
					input = []string{"-l", f}
				}
			}
			if len(input) == 0 {
				input = []string{"-u", target}
			}
			args := append(input,
				"-threads", "500",
				"-timeout", "10",
				"-retries", "3",
				"-status-code",
				"-title",
				"-tech-detect",
				"-tls-probe",
				"-csp-probe",
				"-content-length",
				"-web-server",
				"-ip",
				"-cname",
				"-cdn",
				"-ports", "80,443,8080,8443,8888,3000,5000,9000,9090",
				"-silent",
				"-o", "/tmp/cybermind_httpx.txt",
			)
			return args
		},
	},
	{
		Name:        "whatweb",
		Phase:       4,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install whatweb",
		// Power command: aggression 4, all plugins, JSON output, UA spoof
		BuildArgs: func(target string, ctx *ReconContext) []string {
			t := target
			if len(ctx.LiveURLs) > 0 {
				t = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(t, "http") {
				t = "https://" + t
			}
			return []string{
				"--aggression", "4",
				"--plugins=+all",
				"--colour=never",
				"--log-json=/tmp/cybermind_whatweb.json",
				"--user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				"-v",
				t,
			}
		},
	},
	{
		Name:        "tlsx",
		Phase:       4,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
		// Power command: full TLS fingerprint — JA3, cipher, curve, sig, version, SANs, redirect chain
		BuildArgs: func(target string, ctx *ReconContext) []string {
			var input []string
			if len(ctx.LiveHosts) > 0 {
				f := writeTempList(ctx.LiveHosts)
				if f != "" {
					input = []string{"-l", f}
				}
			}
			if len(input) == 0 {
				input = []string{"-u", target}
			}
			return append(input,
				"-resp",
				"-c",    // certificate
				"-rd",   // redirect chain
				"-ja3",  // JA3 fingerprint
				"-cipher",
				"-curve",
				"-sig",
				"-version",
				"-san",
				"-cn",
				"-so",
				"-threads", "200",
				"-silent",
				"-o", "/tmp/cybermind_tlsx.json",
			)
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 5 — DIRECTORY & ENDPOINT DISCOVERY
	// Goal: find every hidden path, API endpoint, backup file, admin panel
	// Cascade: ffuf (fastest, recursive) → feroxbuster (auto-tune) → gobuster (fallback)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:         "ffuf",
		Phase:        5,
		Timeout:      1800,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install ffuf",
		// Power command: 500 threads, recursive depth 5, auto-calibrate, match all useful codes
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{
				"-w", wl,
				"-u", baseURL + "/FUZZ",
				"-t", "300",
				"-recursion",
				"-recursion-depth", "4",
				"-ac",                    // auto-calibrate
				"-mc", "200,201,204,301,302,307,401,403,405,500",
				"-fc", "404",
				"-timeout", "10",
				"-H", "X-Forwarded-For: 127.0.0.1",
				"-H", "X-Real-IP: 127.0.0.1",
				"-o", "/tmp/cybermind_ffuf.json",
				"-of", "json",
				"-silent",
			}
			if ctx.WAFDetected {
				args = append(args, "-rate", "10", "-p", "0.1")
			}
			return args
		},
	},
	{
		Name:         "feroxbuster",
		Phase:        5,
		Timeout:      1800,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install feroxbuster",
		// Power command: auto-tune, 150 threads, recursive, multiple extensions
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{
				"-u", baseURL,
				"-w", wl,
				"--auto-tune",
				"--threads", "150",
				"-r",                                // follow redirects
				"-x", "php,html,js,txt,json,xml,bak,old,zip,tar,gz,sql,env,config",
				"--depth", "4",
				"--filter-wildcard",
				"--status-codes", "200,201,204,301,302,307,401,403,405",
				"--silent",
				"--no-state",
				"-o", "/tmp/cybermind_ferox.txt",
			}
			if ctx.WAFDetected {
				args = append(args, "--rate-limit", "10")
			}
			return args
		},
	},
	{
		Name:         "gobuster",
		Phase:        5,
		Timeout:      900,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install gobuster",
		// Power command: 100 threads, multiple extensions, recursive, vhost enum
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wl, _ := resolveWordlist()
			baseURL := target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
			}
			if !strings.HasPrefix(baseURL, "http") {
				baseURL = "https://" + baseURL
			}
			args := []string{
				"dir",
				"-u", baseURL,
				"-w", wl,
				"-t", "100",
				"-x", "php,html,js,txt,json,xml,bak,old,zip,env",
				"-r",        // follow redirects
				"-k",        // skip TLS verify
				"-q",        // quiet
				"--no-error",
				"-s", "200,201,204,301,302,307,401,403,405",
				"-b", "404,429",
				"-o", "/tmp/cybermind_gobuster.txt",
			}
			if ctx.WAFDetected {
				args = append(args, "--delay", "200ms")
			}
			return args
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 6 — VULNERABILITY SCANNING
	// Goal: CVEs, misconfigs, exposed secrets, XSS, SQLi, SSRF — full template coverage
	// Order: katana (crawl first) → nuclei (use crawled URLs) → nikto (web server vulns)
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:        "nuclei",
		Phase:       6,
		Timeout:     3600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		// Power command: 500 concurrency, all templates, all tags
		BuildArgs: func(target string, ctx *ReconContext) []string {
			args := []string{
				"-silent", "-no-color", "-stats",
				"-c", "500", "-rl", "100", "-bs", "50",
				"-timeout", "10", "-retries", "3",
				"-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)",
			}
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos", "-severity", "critical,high,medium", "-rl", "20")
			} else {
				args = append(args, "-severity", "critical,high,medium,low,info",
					"-tags", "cve,xss,sqli,ssrf,lfi,rce,xxe,idor,misconfig,exposure,takeover")
			}
			if len(ctx.CrawledURLs) > 0 {
				f := writeTempList(ctx.CrawledURLs)
				if f != "" {
					args = append(args, "-l", f)
					return args
				}
			}
			if len(ctx.LiveURLs) > 0 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					args = append(args, "-l", f)
					return args
				}
			}
			args = append(args, "-u", target)
			return args
		},
		// Fallback 1: critical/high only (faster)
		// Fallback 2: direct target scan with basic templates
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-u", target, "-severity", "critical,high", "-silent", "-no-color", "-c", "200"}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-u", target, "-t", "cves/", "-silent", "-no-color"}
			},
		},
	},
	{
		Name:        "nikto",
		Phase:       6,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "sudo apt install nikto",
		// Power command: all tuning options, SSL, mutation tests, max time 30min
		BuildArgs: func(target string, ctx *ReconContext) []string {
			h := target
			if len(ctx.LiveURLs) > 0 {
				h = ctx.LiveURLs[0]
			}
			return []string{
				"-h", h,
				"-Tuning", "x,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,0,1,2,3,4,5,6,7,8,9",
				"-ssl",
				"-mutate", "1,2,3,4,5,6",
				"-useragent", "Mozilla/5.0 (compatible; Googlebot/2.1)",
				"-maxtime", "1800",
				"-nointeractive",
				"-Format", "json",
				"-output", "/tmp/cybermind_nikto.json",
			}
		},
	},
	{
		Name:        "katana",
		Phase:       6,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		// Power command: depth 5, 300 concurrency, JS crawl, form fill, headless-ready
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Use all live URLs if available for maximum coverage
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-list", f,
						"-d", "5",
						"-c", "300",
						"-jc",        // parse JS files
						"-kf", "all", // known files
						"-aff",       // automatic form fill
						"-no-color",
						"-silent",
						"-o", "/tmp/cybermind_katana.txt",
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
				"-d", "5",
				"-c", "300",
				"-jc", "-kf", "all", "-aff",
				"-no-color",
				"-silent",
				"-o", "/tmp/cybermind_katana.txt",
			}
		},
	},
}

// ToolNames returns all tool names in the registry.
func ToolNames() []string {
	names := make([]string, len(toolRegistry))
	for i, spec := range toolRegistry {
		names[i] = spec.Name
	}
	return names
}

// writeTempList writes a slice of strings to a temp file and returns the path.
// Uses 0600 permissions — temp files may contain sensitive target data.
func writeTempList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	f, err := os.CreateTemp("", "cybermind-list-*.txt")
	if err != nil {
		return ""
	}
	// Secure permissions before writing
	f.Chmod(0600)
	defer f.Close()
	for _, item := range items {
		f.WriteString(item + "\n")
	}
	return f.Name()
}

// portStr converts int slice to comma-separated port string
func portStr(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(s, ",")
}
