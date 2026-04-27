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

	// ── Shodan CLI — internet-wide host intelligence ──────────────────────────
	// Queries Shodan for open ports, CVEs, banners, tags on target IPs
	// Requires SHODAN_API_KEY env var (free tier available at shodan.io)
	{
		Name:        "shodan",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  false,
		InstallHint: "pip3 install shodan setuptools --break-system-packages && shodan init YOUR_API_KEY",
		// Fixed: shodan pkg_resources issue — ensure setuptools is installed
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.LiveHosts) > 0 {
				return []string{"host", ctx.LiveHosts[0]}
			}
			return []string{"host", target}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"search", "--fields", "ip_str,port,org,os", "hostname:" + target}
			},
		},
	},

	// ── h8mail — email OSINT + breach hunting ────────────────────────────────
	// Finds breached credentials, email addresses, and associated data
	// Uses free APIs: HaveIBeenPwned, Hunter.io, Snusbase
	{
		Name:        "h8mail",
		Phase:       1,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "pip3 install h8mail --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-t", target,
				"--json", "/tmp/cybermind_h8mail.json",
				"-q",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-t", target, "-q"}
			},
		},
	},

	// ── exiftool — metadata extraction from web files ────────────────────────
	// Extracts GPS, author, software, creation date from images/docs
	// Finds leaked internal paths, usernames, software versions
	{
		Name:        "exiftool",
		Phase:       1,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y libimage-exiftool-perl",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Download and analyze files from target
			// First try to find downloadable files via wayback
			outDir := "/tmp/cybermind_exiftool_" + target
			return []string{
				"-r",          // recursive
				"-json",       // JSON output
				"-all",        // all metadata
				"-q",          // quiet
				outDir,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				// Analyze any already-downloaded files
				return []string{"-json", "-all", "/tmp/cybermind_exiftool_" + target}
			},
		},
	},

	// ── metagoofil — document metadata harvesting ────────────────────────────
	// Downloads public documents (PDF, DOCX, XLSX) and extracts metadata
	// Finds: usernames, email addresses, software versions, internal paths
	{
		Name:        "metagoofil",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y metagoofil",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			outDir := "/tmp/cybermind_metagoofil_" + target
			// Create output dir BEFORE running — metagoofil fails if dir doesn't exist
			os.MkdirAll(outDir, 0755)
			return []string{
				"-d", target,
				"-t", "pdf,doc,docx,xls,xlsx,ppt,pptx",
				"-l", "50",
				"-n", "20",
				"-o", outDir,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_metagoofil_" + target
				os.MkdirAll(outDir, 0755)
				return []string{"-d", target, "-t", "pdf,doc,docx", "-l", "20", "-n", "10", "-o", outDir}
			},
		},
	},

	// ── spiderfoot — automated OSINT framework ───────────────────────────────
	// 200+ modules: DNS, WHOIS, email, social media, dark web, breach data
	// CLI mode: spiderfoot -s target -m all -o /tmp/output.json
	{
		Name:        "spiderfoot",
		Phase:       1,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y spiderfoot",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-s", target,
				"-m", "sfp_dns,sfp_whois,sfp_email,sfp_pgp,sfp_shodan,sfp_hunter,sfp_haveibeenpwned,sfp_linkedin,sfp_twitter,sfp_github",
				"-o", "json",
				"-q",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-s", target, "-m", "sfp_dns,sfp_whois,sfp_email", "-o", "json", "-q"}
			},
		},
	},

	// ── recon-ng — modular web reconnaissance framework ──────────────────────
	// Marketplace of 100+ modules for OSINT, DNS, social media, breach data
	{
		Name:        "recon-ng",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y recon-ng",
		// Fixed: recon-ng uses -r <script_file> not -x for batch commands
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Write batch script to temp file
			scriptPath := "/tmp/cybermind_reconng_" + target + ".rc"
			script := fmt.Sprintf(
				"workspaces create %s\n"+
					"modules load recon/domains-hosts/hackertarget\nrun\n"+
					"modules load recon/domains-hosts/certificate_transparency\nrun\n"+
					"show hosts\n",
				target)
			os.WriteFile(scriptPath, []byte(script), 0600)
			return []string{"-w", target, "-r", scriptPath}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				scriptPath := "/tmp/cybermind_reconng_fb_" + target + ".rc"
				script := fmt.Sprintf("workspaces create %s\nmodules load recon/domains-hosts/hackertarget\nrun\nshow hosts\n", target)
				os.WriteFile(scriptPath, []byte(script), 0600)
				return []string{"-w", target, "-r", scriptPath}
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
		// Fixed: removed -maxnets (removed in amass v4+), use -timeout instead
		BuildArgs: func(target string, ctx *ReconContext) []string {
			bruteList := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(bruteList); err == nil {
				return []string{
					"enum",
					"-d", target,
					"-passive",
					"-brute",
					"-w", bruteList,
					"-timeout", "15",
					"-o", "/tmp/cybermind_amass.txt",
				}
			}
			return []string{
				"enum",
				"-passive",
				"-d", target,
				"-timeout", "15",
				"-o", "/tmp/cybermind_amass.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"enum", "-passive", "-d", target, "-timeout", "10"}
			},
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
		Timeout:     21600, // 6 hours max — full exhaustive mode, no shortcuts
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh && sudo tee /usr/local/bin/reconftw > /dev/null << 'EOF'\n#!/bin/bash\ncd /opt/reconftw && bash reconftw.sh \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/reconftw",
		// PRIMARY: ALL mode — reconftw's actual supported flags
		// -a  = all modules
		// --deep = maximum depth
		// --parallel = parallel execution
		// These are the REAL reconftw flags (verified against reconftw.sh source)
		// NOTE: reconftw takes 4-6 hours in -a mode. Only run in overnight mode.
		// In quick/deep mode, individual tools (subfinder, amass, dnsx) cover the same ground faster.
		BuildArgs: func(target string, ctx *ReconContext) []string {
			outDir := "/tmp/cybermind_reconftw_" + target
			// Check execution mode — skip reconftw in quick/deep, only overnight
			mode := os.Getenv("CYBERMIND_MODE")
			if mode == "quick" || mode == "deep" || mode == "" {
				// Return empty to trigger fallback skip
				return nil
			}
			os.MkdirAll(outDir, 0755)
			return []string{
				"-d", target,
				"-r",          // full recon (not -a which is too slow)
				"--parallel",  // parallel execution
				"-o", outDir,
			}
		},
		// Fallback 1: subdomain + web only (-s) — faster
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				os.MkdirAll(outDir, 0755)
				return []string{
					"-d", target,
					"-s",
					"--parallel",
					"-o", outDir,
				}
			},
			// Fallback 2: passive only (-p) — stealthy, no active probing
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				os.MkdirAll(outDir, 0755)
				return []string{
					"-d", target,
					"-p",
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
		// Fixed: removed -wildcard-filter (removed in newer dnsx versions)
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{
						"-l", f,
						"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt",
						"-resp",
						"-resp-only",
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
				"-t", "200",
				"-silent",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-a", "-resp", "-silent"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — PORT SCANNING
	// Goal: find every open port, service version, OS, WAF — full coverage
	// Cascade: naabu (primary, fast+nmap) → nmap (deepest)
	// masscan runs independently (no cascade) for ultra-fast initial sweep
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name:         "naabu",
		Phase:        3,
		Timeout:      600,
		CascadeGroup: "portscan",
		InstallHint:  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		// Fixed: -t → -c (threads flag renamed in newer naabu)
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-host", target,
				"-p", "80,443,8080,8443,8888,3000,5000,9000,9090,3306,5432,6379,27017,22,21,25,53,110,143,445,3389",
				"-c", "500",
				"-rate", "5000",
				"-retries", "2",
				"-silent",
				"-o", "/tmp/cybermind_naabu.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{
					"-host", target,
					"-top-ports", "1000",
					"-c", "100",
					"-silent",
				}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-host", target, "-top-ports", "100", "-silent"}
			},
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

	// ── NEW: ZMap — Internet-wide host discovery (45 min for full IPv4) ──────
	// Runs independently alongside masscan — different approach (single-packet)
	// Best for: wide-scope bug bounty programs, CIDR range scanning
	{
		Name:        "zmap",
		Phase:       3,
		Timeout:     300,
		InstallHint: "sudo apt install zmap -y",
		// Power command: scan common web ports, output live IPs for httpx
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-p", "80,443,8080,8443,8888,3000,5000,9000",
				"--output-filter", "success = 1",
				"-o", "/tmp/cybermind_zmap.csv",
				"-f", "saddr,sport,daddr",
				"--rate", "10000", // 10k pps — safe for most networks
				"--cooldown-time", "3",
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{
					"-p", "80,443",
					"-o", "/tmp/cybermind_zmap.csv",
					"--rate", "1000",
					target,
				}
			},
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
	// whatweb removed — httpx already does tech detection with -tech-detect flag
	// Use: httpx -tech-detect instead
	{
		Name:        "tlsx",
		Phase:       4,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
		// Fixed: removed -resp (flag removed), -rd, -so (not in all versions)
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
				"-c",       // certificate
				"-ja3",     // JA3 fingerprint
				"-cipher",
				"-version",
				"-san",
				"-cn",
				"-threads", "200",
				"-silent",
				"-o", "/tmp/cybermind_tlsx.json",
			)
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if len(ctx.LiveHosts) > 0 {
					u = ctx.LiveHosts[0]
				}
				return []string{"-u", u, "-san", "-cn", "-silent"}
			},
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
		Timeout:      600,
		DomainOnly:   true,
		CascadeGroup: "dirfuzz",
		NeedsFile:    "wordlist",
		InstallHint:  "sudo apt install ffuf",
		// Fixed: removed -recursion (causes ffuf to hang), reduced threads
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
				"-t", "100",
				"-ac",
				"-mc", "200,201,204,301,302,307,401,403,405,500",
				"-fc", "404",
				"-timeout", "10",
				"-o", "/tmp/cybermind_ffuf.json",
				"-of", "json",
				"-s",
			}
			if ctx.WAFDetected {
				args = append(args, "-rate", "10", "-p", "0.1")
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				wl, _ := resolveWordlist()
				baseURL := target
				if len(ctx.LiveURLs) > 0 {
					baseURL = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(baseURL, "http") {
					baseURL = "https://" + baseURL
				}
				return []string{"-w", wl, "-u", baseURL + "/FUZZ", "-t", "50", "-ac", "-s"}
			},
		},
	},
	{
		Name:         "feroxbuster",
		Phase:        5,
		Timeout:      600,
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
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
		// Fixed: reduced concurrency from 500 to 50 to avoid "higher than max-host-error"
		BuildArgs: func(target string, ctx *ReconContext) []string {
			args := []string{
				"-silent", "-no-color", "-stats",
				"-c", "50", "-rl", "50", "-bs", "25",
				"-timeout", "10", "-retries", "2",
				"-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)",
			}
			if ctx.WAFDetected {
				args = append(args, "-etags", "fuzzing,dos", "-severity", "critical,high,medium", "-rl", "10")
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
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-u", target, "-severity", "critical,high", "-silent", "-no-color", "-c", "25"}
			},
			func(target string, ctx *ReconContext) []string {
				return []string{"-u", target, "-t", "cves/", "-silent", "-no-color", "-c", "10"}
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
		// Fixed: reduced concurrency from 300 to 50 to prevent being killed
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.LiveURLs) > 1 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return []string{
						"-list", f,
						"-d", "3",
						"-c", "50",
						"-jc",
						"-kf", "all",
						"-no-color",
						"-silent",
						"-timeout", "10",
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
				"-d", "3",
				"-c", "50",
				"-jc", "-kf", "all",
				"-no-color",
				"-silent",
				"-timeout", "10",
				"-o", "/tmp/cybermind_katana.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if len(ctx.LiveURLs) > 0 {
					u = ctx.LiveURLs[0]
				}
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "-d", "2", "-c", "20", "-silent", "-timeout", "10"}
			},
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
