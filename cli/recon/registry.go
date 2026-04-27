package recon

import (
	"fmt"
	"os"
	"os/exec"
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
			// Auto-fix pkg_resources before running shodan
			exec.Command("pip3", "install", "setuptools", "--break-system-packages", "-q").Run()
			if len(ctx.LiveHosts) > 0 {
				return []string{"host", ctx.LiveHosts[0]}
			}
			return []string{"host", target}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"search", "--fields", "ip_str,port,org,os,vulns", "hostname:" + target}
			},
			// Fallback 2: use shodan InternetDB via curl (free, no key needed)
			func(target string, ctx *ReconContext) []string {
				// This fallback uses shodan host with --no-error flag
				// Returns ports, CVEs, tags for the IP
				ip := target
				if len(ctx.LiveHosts) > 0 {
					ip = ctx.LiveHosts[0]
				}
				return []string{"host", ip, "--no-error"}
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
			// metagoofil needs results.html parent dir to exist
			os.WriteFile(outDir+"/results.html", []byte(""), 0644)
			return []string{
				"-d", target,
				"-t", "pdf,doc,docx,xls,xlsx,ppt,pptx",
				"-l", "50",
				"-n", "20",
				"-o", outDir,
				"-r", outDir + "/results.html",
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
				"-t", "100",
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
			// Fallback 2: active mode without brute
			func(target string, ctx *ReconContext) []string {
				return []string{"enum", "-active", "-d", target, "-timeout", "10"}
			},
		},
	},
	// reconftw — PHASE 2 MEGA TOOL — full reconFTW power unleashed
	// reconftw is a meta-tool that internally runs 50+ tools across ALL phases:
	// OSINT, passive enum, cert transparency, brute force, permutations, web probing,
	// vuln scanning, JS analysis, parameter discovery, cloud buckets, takeover checks,
	// GitHub dorking, WAF detection, screenshot capture, and much more.
	//
	// Mode-aware execution:
	//   quick     → -s (subdomain only, ~15 min, passive sources)
	//   deep      → -r --parallel (full recon, ~2-4 hours, all active tools)
	//   overnight → -a --deep --parallel (ALL modules exhaustive, ~6-12 hours)
	//
	// reconftw output structure (all parsed by CyberMind):
	//   subdomains/  → passive, brute, permutations, crt, takeover candidates
	//   webs/        → live URLs, katana crawl, waymore passive, JS files
	//   vulns/       → nuclei findings, XSS, SQLi, SSRF, LFI, SSTI, CRLF
	//   osint/       → emails, API keys, GitHub secrets, cloud buckets
	//   hosts/       → open ports, services, WAF detection, CDN info
	//   screenshots/ → visual recon of all live web targets
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
		Timeout:     43200, // 12 hours max — overnight exhaustive mode
		DomainOnly:  true,
		InstallHint: "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh && sudo tee /usr/local/bin/reconftw > /dev/null << 'EOF'\n#!/bin/bash\ncd /opt/reconftw && bash reconftw.sh \"$@\"\nEOF\nsudo chmod +x /usr/local/bin/reconftw",
		// PRIMARY: mode-aware — reads CYBERMIND_MODE env to select the right flags
		// quick     → -s (subdomain passive only, fastest)
		// deep      → -r --parallel (full recon, all active tools)
		// overnight → -a --deep --parallel (ALL modules, maximum depth)
		// default   → -r --parallel (full recon, safe default)
		BuildArgs: func(target string, ctx *ReconContext) []string {
			outDir := "/tmp/cybermind_reconftw_" + target
			mode := os.Getenv("CYBERMIND_MODE")
			os.MkdirAll(outDir, 0755)

			// Write a reconftw config override to maximize output parsing
			reconCfg := "/tmp/cybermind_reconftw_cfg_" + target + ".cfg"
			cfgContent := fmt.Sprintf(`# CyberMind reconftw config override
NOTIFY=false
DEEP=true
PERMUTATIONS=true
PERMUTATIONS_OPTION="gotator"
FUZZING=true
NUCLEI_SEVERITY="critical,high,medium,low"
NUCLEI_TEMPLATES_PATH="$HOME/nuclei-templates"
NUCLEI_FLAGS="-stats -no-color"
SCREENSHOT=true
OSINT=true
GITHUB_DORKING=true
CLOUD_ENUM=true
SUBDOMAIN_TAKEOVER=true
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS_FILE="/tmp/cybermind_resolvers.txt"
AXIOM=false
DIFF=false
INSCOPE=false
OUTDIR="%s"
`, outDir)
			os.WriteFile(reconCfg, []byte(cfgContent), 0600)

			switch mode {
			case "quick":
				// Subdomain passive only — fast, no active probing
				return []string{"-d", target, "-s", "--parallel", "-o", outDir}
			case "overnight", "12h":
				// ALL modules — maximum depth, exhaustive
				return []string{
					"-d", target,
					"-a",         // ALL modules
					"--deep",     // maximum depth
					"--parallel", // parallel execution
					"-o", outDir,
				}
			default: // deep or unset
				// Full recon — all active tools, parallel
				return []string{
					"-d", target,
					"-r",         // full recon (subdomains + web + vulns)
					"--parallel", // parallel execution
					"-o", outDir,
				}
			}
		},
		// Fallback 1: subdomain + web only (-s) — faster, still gets live URLs
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				os.MkdirAll(outDir, 0755)
				return []string{
					"-d", target,
					"-s",         // subdomain + web
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
					"-p",         // passive only
					"-o", outDir,
				}
			},
			// Fallback 3: OSINT only (-o flag conflicts with outdir, use --osint)
			func(target string, ctx *ReconContext) []string {
				outDir := "/tmp/cybermind_reconftw_" + target
				os.MkdirAll(outDir, 0755)
				return []string{
					"-d", target,
					"--osint",    // OSINT modules only
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
		// Added -wd for wildcard detection instead
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{
						"-l", f,
						"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt",
						"-resp",
						"-resp-only",
						"-wd",        // wildcard detection
						"-t", "500",  // threads
						"-retry", "2",
						"-silent",
						"-o", "/tmp/cybermind_dnsx.txt",
					}
				}
			}
			return []string{
				"-d", target,
				"-a", "-aaaa", "-cname", "-ns", "-mx", "-txt",
				"-resp",
				"-wd",
				"-t", "200",
				"-retry", "2",
				"-silent",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-a", "-resp", "-silent"}
			},
			// Fallback 2: minimal - just A records
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-a", "-silent"}
			},
		},
	},

	// ── puredns — fast DNS brute-force with wildcard filtering ───────────────
	{
		Name:        "puredns",
		Phase:       2,
		Timeout:     1800,
		DomainOnly:  true,
		InstallHint: "go install github.com/d3mondev/puredns/v2@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(wordlist); err != nil {
				wordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			resolvers := "/tmp/cybermind_resolvers.txt"
			if _, err := os.Stat(resolvers); err != nil {
				resolvers = ""
			}
			args := []string{
				"bruteforce", wordlist, target,
				"--threads", "100",
				"--rate-limit", "1000",
				"--write", "/tmp/cybermind_puredns.txt",
			}
			if resolvers != "" {
				args = append(args, "--resolvers", resolvers)
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
				if _, err := os.Stat(wordlist); err != nil {
					wordlist = "/usr/share/wordlists/dirb/common.txt"
				}
				return []string{"bruteforce", wordlist, target, "--threads", "50"}
			},
		},
	},
	// ── alterx — AI-based subdomain permutation engine ───────────────────────
	{
		Name:        "alterx",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{
						"-l", f,
						"-enrich",
						"-silent",
						"-o", "/tmp/cybermind_alterx.txt",
					}
				}
			}
			return []string{
				"-d", target,
				"-enrich",
				"-silent",
				"-o", "/tmp/cybermind_alterx.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2.5 — CRAWLING + URL COLLECTION
	// Goal: collect ALL historical URLs, crawl live subdomains, extract endpoints
	// Tools: gau, waybackurls, waymore, hakrawler, cariddi, crt.sh
	// ══════════════════════════════════════════════════════════════════════════

	// ── crt.sh — Certificate Transparency direct API ──────────────────────────
	{
		Name:        "curl",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "sudo apt install curl",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-s", "--max-time", "30",
				"-H", "Accept: application/json",
				fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target),
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-s", "--max-time", "20", fmt.Sprintf("https://crt.sh/?q=%%25.%s", target)}
			},
		},
	},

	// ── asnmap — ASN to IP range discovery ───────────────────────────────────
	{
		Name:        "asnmap",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-d", target,
				"-json",
				"-silent",
				"-o", "/tmp/cybermind_asnmap.json",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},
	// ── github-subdomains — find subdomains in GitHub code ───────────────────
	{
		Name:        "github-subdomains",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/gwen001/github-subdomains@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			token := os.Getenv("GITHUB_TOKEN")
			if token == "" {
				return []string{"-d", target, "-silent", "-o", "/tmp/cybermind_github_subs.txt"}
			}
			return []string{
				"-d", target,
				"-t", token,
				"-silent",
				"-o", "/tmp/cybermind_github_subs.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},

	// ── gau — Get All URLs from Wayback + OTX + CommonCrawl ──────────────────
	{
		Name:        "gau",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"--subs",
				"--threads", "20",
				"--blacklist", "png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3",
				"--providers", "wayback,otx,commoncrawl,urlscan",
				"--retries", "2",
				"--o", "/tmp/cybermind_gau_recon.txt",
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"--subs", "--threads", "10", "--o", "/tmp/cybermind_gau_recon.txt", target}
			},
		},
	},

	// ── waybackurls — Wayback Machine URL collection ──────────────────────────
	{
		Name:        "waybackurls",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{target}
		},
	},

	// ── hakrawler — Fast Go crawler, JS-aware ────────────────────────────────
	{
		Name:        "hakrawler",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/hakluke/hakrawler@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-url", u, "-depth", "3", "-plain", "-subs", "-js", "-forms"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-url", u, "-depth", "2", "-plain"}
			},
		},
	},

	// ── cariddi — Deep crawler + secrets + endpoints extractor ───────────────
	{
		Name:        "cariddi",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/edoardottt/cariddi/cmd/cariddi@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-s", u, "-e", "-ef", "2", "-secrets", "-c", "30", "-d", "3"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-s", u, "-e", "-c", "10", "-d", "2"}
			},
		},
	},

	// ── waymore — Passive URL collection ─────────────────────────────────────
	{
		Name:        "waymore",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "pip3 install waymore --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-i", target, "-mode", "U",
				"-oU", "/tmp/cybermind_waymore_recon.txt",
				"-t", "20", "-p", "wayback,otx,commoncrawl,urlscan",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-i", target, "-mode", "U", "-oU", "/tmp/cybermind_waymore_recon.txt"}
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
				"-c", "500",      // concurrency (renamed from -t)
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
				return []string{"-host", target, "-top-ports", "100", "-c", "50", "-silent"}
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
				"-threads", "150",
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
		// Fixed: removed -resp, -rd, -so (flags removed in newer versions)
		// Kept only stable flags that work across versions
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
				"-san",     // subject alternative names
				"-cn",      // common name
				"-org",     // organization
				"-cipher",  // cipher suites
				"-hash", "sha256", // certificate hash
				"-jarm",    // JARM fingerprint
				"-ja3",     // JA3 fingerprint
				"-tls-version", // TLS version
				"-c", "200", // concurrency
				"-silent",
				"-j",       // JSON output
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
			// Fallback 2: minimal - just SAN
			func(target string, ctx *ReconContext) []string {
				u := target
				if len(ctx.LiveHosts) > 0 {
					u = ctx.LiveHosts[0]
				}
				return []string{"-u", u, "-san", "-silent"}
			},
		},
	},

	// ── VhostFinder — virtual host discovery via HTTP Host header fuzzing ──────
	{
		Name:        "ffuf-vhost",
		Phase:       4,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "sudo apt install ffuf",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Use ffuf for vhost fuzzing with wordlist
			wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(wordlist); err != nil {
				wordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			baseURL := "https://" + target
			if len(ctx.LiveURLs) > 0 {
				baseURL = ctx.LiveURLs[0]
				// Strip path
				if idx := strings.Index(baseURL[8:], "/"); idx > 0 {
					baseURL = baseURL[:8+idx]
				}
			}
			return []string{
				"-w", wordlist,
				"-u", baseURL,
				"-H", "Host: FUZZ." + target,
				"-t", "100",
				"-ac",
				"-mc", "200,201,204,301,302,307,401,403",
				"-fc", "404",
				"-s",
				"-o", "/tmp/cybermind_vhost.json",
				"-of", "json",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
				if _, err := os.Stat(wordlist); err != nil {
					wordlist = "/usr/share/wordlists/dirb/common.txt"
				}
				return []string{
					"-w", wordlist,
					"-u", "https://" + target,
					"-H", "Host: FUZZ." + target,
					"-t", "50",
					"-ac",
					"-s",
				}
			},
		},
	},

	// ── webanalyze — Go-based Wappalyzer (1500+ tech signatures) ─────────────
	{
		Name:        "webanalyze",
		Phase:       4,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/rverton/webanalyze/cmd/webanalyze@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-host", u, "-crawl", "2", "-output", "/tmp/cybermind_webanalyze.json"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-host", u}
			},
		},
	},
	// ── favirecon — favicon hash → technology detection ───────────────────────
	{
		Name:        "favirecon",
		Phase:       4,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/edoardottt/favirecon/cmd/favirecon@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{"-u", u, "-t", "50", "-silent"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "-silent"}
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
				"-c", "25", "-rl", "25", "-bs", "10",
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

// ─── TIER 1 TOOLS ─────────────────────────────────────────────────────────────
// These are the highest-impact missing tools added in v5.0.0

// ── wafw00f — WAF detection (Phase 1 passive) ─────────────────────────────────
var tier1Tools = []ToolSpec{
	{
		Name:        "wafw00f",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "pip3 install wafw00f --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{u, "-a", "-o", "/tmp/cybermind_wafw00f.json", "--format", "json"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{u, "-a"}
			},
		},
	},
	// ── emailfinder — email discovery from target domain ──────────────────────
	{
		Name:        "emailfinder",
		Phase:       1,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "pip3 install emailfinder --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"--domain", target}
			},
		},
	},
	// ── dnsrecon — DNS enumeration (zone transfer, brute, reverse) ────────────
	{
		Name:        "dnsrecon",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y dnsrecon",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-d", target,
				"-t", "std,brt,axfr,rvl,snoop,tld",
				"--xml", "/tmp/cybermind_dnsrecon.xml",
				"-j", "/tmp/cybermind_dnsrecon.json",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target, "-t", "std,axfr"}
			},
		},
	},
	// ── spoofcheck — email spoofing check (SPF/DMARC) ─────────────────────────
	{
		Name:        "spoofcheck",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "pip3 install spoofcheck --break-system-packages || git clone https://github.com/BishopFox/spoofcheck /opt/spoofcheck && pip3 install -r /opt/spoofcheck/requirements.txt --break-system-packages && sudo ln -sf /opt/spoofcheck/spoofcheck.py /usr/local/bin/spoofcheck",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{target}
		},
	},
	// ── uncover — Shodan+Fofa+Censys+Hunter aggregator ────────────────────────
	{
		Name:        "uncover",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-q", "hostname:" + target,
				"-e", "shodan,censys,fofa,hunter",
				"-silent",
				"-o", "/tmp/cybermind_uncover.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-q", "hostname:" + target, "-e", "shodan", "-silent"}
			},
		},
	},
	// ── shuffledns — mass DNS resolver with custom resolvers ──────────────────
	{
		Name:        "shuffledns",
		Phase:       2,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
			if _, err := os.Stat(wordlist); err != nil {
				wordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			resolvers := "/tmp/cybermind_resolvers.txt"
			if _, err := os.Stat(resolvers); err != nil {
				resolvers = ""
			}
			args := []string{
				"-d", target,
				"-w", wordlist,
				"-t", "500",
				"-silent",
				"-o", "/tmp/cybermind_shuffledns.txt",
			}
			if resolvers != "" {
				args = append(args, "-r", resolvers)
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				wordlist := "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
				if _, err := os.Stat(wordlist); err != nil {
					wordlist = "/usr/share/wordlists/dirb/common.txt"
				}
				return []string{"-d", target, "-w", wordlist, "-t", "200", "-silent"}
			},
		},
	},
	// ── cdncheck — CDN/WAF/cloud provider detection ───────────────────────────
	{
		Name:        "cdncheck",
		Phase:       4,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			var input []string
			if len(ctx.LiveHosts) > 0 {
				f := writeTempList(ctx.LiveHosts)
				if f != "" {
					input = []string{"-l", f}
				}
			}
			if len(input) == 0 {
				input = []string{"-i", target}
			}
			return append(input, "-resp", "-silent", "-o", "/tmp/cybermind_cdncheck.txt")
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-i", target, "-silent"}
			},
		},
	},
	// ── smap — passive port scan via Shodan data (no noise) ──────────────────
	{
		Name:        "smap",
		Phase:       3,
		Timeout:     120,
		DomainOnly:  false,
		InstallHint: "go install github.com/s0md3v/smap/cmd/smap@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-iL", func() string {
					if len(ctx.LiveHosts) > 0 {
						f := writeTempList(ctx.LiveHosts)
						if f != "" {
							return f
						}
					}
					return "/dev/stdin"
				}(),
				"-oJ", "/tmp/cybermind_smap.json",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{target, "-oJ", "/tmp/cybermind_smap.json"}
			},
		},
	},
	// ── rustscan — ultra-fast port scanner ────────────────────────────────────
	{
		Name:         "rustscan",
		Phase:        3,
		Timeout:      300,
		CascadeGroup: "portscan",
		InstallHint:  "cargo install rustscan || sudo apt install -y rustscan",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-a", target,
				"--ulimit", "5000",
				"-b", "1500",
				"--timeout", "3000",
				"--", "-sV", "-sC", "--script", "vuln",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-a", target, "--ulimit", "2000", "-b", "500"}
			},
		},
	},
	// ── trufflehog — secrets in GitHub/web (recon phase) ─────────────────────
	{
		Name:        "trufflehog",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"github",
				"--org=" + target,
				"--json",
				"--no-update",
				"--only-verified",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"git", u, "--json", "--no-update"}
			},
		},
	},
	// ── cloud_enum — S3/Azure/GCP bucket enumeration ──────────────────────────
	{
		Name:        "cloud_enum",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "pip3 install cloud-enum --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Strip TLD for bucket name guessing
			keyword := target
			if idx := strings.LastIndex(target, "."); idx > 0 {
				keyword = target[:idx]
			}
			return []string{
				"-k", keyword,
				"-k", target,
				"--disable-azure", // start with S3 only for speed
				"-l", "/tmp/cybermind_cloud_enum.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				keyword := target
				if idx := strings.LastIndex(target, "."); idx > 0 {
					keyword = target[:idx]
				}
				return []string{"-k", keyword, "-l", "/tmp/cybermind_cloud_enum.txt"}
			},
		},
	},
	// ── dnstake — subdomain takeover detection ────────────────────────────────
	{
		Name:        "dnstake",
		Phase:       6,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/pwnesia/dnstake/cmd/dnstake@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return []string{"-f", f, "-c", "50", "-s"}
				}
			}
			return []string{"-h", target, "-s"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-h", target}
			},
		},
	},
	// ── nuclei takeovers — subdomain takeover via nuclei templates ────────────
	{
		Name:        "nuclei-takeover",
		Phase:       6,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			args := []string{
				"-t", "takeovers/",
				"-silent", "-no-color",
				"-c", "25", "-rl", "25",
				"-o", "/tmp/cybermind_nuclei_takeover.txt",
			}
			if len(ctx.Subdomains) > 0 {
				f := writeTempList(ctx.Subdomains)
				if f != "" {
					return append(args, "-l", f)
				}
			}
			return append(args, "-u", target)
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-t", "takeovers/", "-u", target, "-silent", "-no-color", "-c", "10"}
			},
		},
	},
	// ── nuclei tokens — exposed secrets/tokens via nuclei ─────────────────────
	{
		Name:        "nuclei-tokens",
		Phase:       6,
		Timeout:     600,
		DomainOnly:  true,
		InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			args := []string{
				"-t", "exposures/tokens/",
				"-t", "exposures/apis/",
				"-t", "exposures/configs/",
				"-silent", "-no-color",
				"-c", "25", "-rl", "25",
				"-o", "/tmp/cybermind_nuclei_tokens.txt",
			}
			if len(ctx.LiveURLs) > 0 {
				f := writeTempList(ctx.LiveURLs)
				if f != "" {
					return append(args, "-l", f)
				}
			}
			return append(args, "-u", target)
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-t", "exposures/", "-u", target, "-silent", "-no-color", "-c", "10"}
			},
		},
	},

	// ─── TIER 2 TOOLS ─────────────────────────────────────────────────────────

	// ── ctfr — Certificate Transparency subdomain finder ──────────────────────
	{
		Name:        "ctfr",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "pip3 install ctfr --break-system-packages || git clone https://github.com/UnaPibaGeek/ctfr /opt/ctfr && pip3 install -r /opt/ctfr/requirements.txt --break-system-packages && sudo ln -sf /opt/ctfr/ctfr.py /usr/local/bin/ctfr",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target, "-o", "/tmp/cybermind_ctfr.txt"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target}
			},
		},
	},
	// ── mapcidr — CIDR manipulation + expansion ───────────────────────────────
	{
		Name:        "mapcidr",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  false,
		InstallHint: "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Expand ASN ranges from asnmap output
			asnFile := "/tmp/cybermind_asnmap.json"
			if _, err := os.Stat(asnFile); err == nil {
				return []string{"-cl", asnFile, "-silent", "-o", "/tmp/cybermind_mapcidr_ips.txt"}
			}
			return []string{"-cidr", target + "/24", "-silent"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-cidr", target + "/24", "-silent"}
			},
		},
	},
	// ── ipinfo — IP geolocation + ASN + org ───────────────────────────────────
	{
		Name:        "ipinfo",
		Phase:       1,
		Timeout:     60,
		DomainOnly:  false,
		InstallHint: "pip3 install ipinfo --break-system-packages || go install github.com/ipinfo/cli/ipinfo@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			if len(ctx.LiveHosts) > 0 {
				return []string{ctx.LiveHosts[0], "--json"}
			}
			return []string{target, "--json"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{target}
			},
		},
	},
	// ── sslscan — SSL/TLS configuration analysis ──────────────────────────────
	{
		Name:        "sslscan",
		Phase:       4,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y sslscan",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"--no-colour",
				"--xml=/tmp/cybermind_sslscan.xml",
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"--no-colour", target}
			},
		},
	},
	// ── uro — URL deduplication + pattern analysis ────────────────────────────
	{
		Name:        "uro",
		Phase:       2,
		Timeout:     60,
		DomainOnly:  true,
		InstallHint: "pip3 install uro --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// uro reads from stdin — pipe all collected URLs through it
			allURLFiles := []string{
				"/tmp/cybermind_gau_recon.txt",
				"/tmp/cybermind_waymore_recon.txt",
			}
			for _, f := range allURLFiles {
				if _, err := os.Stat(f); err == nil {
					return []string{"-i", f, "-o", "/tmp/cybermind_uro_deduped.txt"}
				}
			}
			return []string{"-o", "/tmp/cybermind_uro_deduped.txt"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-o", "/tmp/cybermind_uro_deduped.txt"}
			},
		},
	},
	// ── misconfig-mapper — third-party service misconfiguration detection ──────
	{
		Name:        "misconfig-mapper",
		Phase:       6,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{
				"-target", target,
				"-service", "all",
				"-output", "/tmp/cybermind_misconfig.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-target", target}
			},
		},
	},
	// ── second-order — broken link hijacking detection ────────────────────────
	{
		Name:        "second-order",
		Phase:       6,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/mhmdiaa/second-order@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-base", u,
				"-config", "/tmp/cybermind_second_order_config.json",
				"-output", "/tmp/cybermind_second_order.json",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-base", u}
			},
		},
	},

	// ─── TIER 3 TOOLS ─────────────────────────────────────────────────────────

	// ── crosslinked — LinkedIn employee enumeration ───────────────────────────
	{
		Name:        "crosslinked",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "pip3 install crosslinked --break-system-packages",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Extract company name from domain
			company := target
			if idx := strings.Index(target, "."); idx > 0 {
				company = target[:idx]
			}
			return []string{
				"-f", "{first}.{last}@" + target,
				company,
				"-o", "/tmp/cybermind_crosslinked.txt",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				company := target
				if idx := strings.Index(target, "."); idx > 0 {
					company = target[:idx]
				}
				return []string{company, "-o", "/tmp/cybermind_crosslinked.txt"}
			},
		},
	},
	// ── enum4linux-ng — SMB/LDAP enumeration ──────────────────────────────────
	{
		Name:        "enum4linux-ng",
		Phase:       3,
		Timeout:     300,
		DomainOnly:  false,
		InstallHint: "pip3 install enum4linux-ng --break-system-packages || sudo apt install -y enum4linux",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Only run if SMB port is open
			for _, p := range ctx.OpenPorts {
				if p == 445 || p == 139 {
					return []string{"-A", "-C", target, "-oJ", "/tmp/cybermind_enum4linux.json"}
				}
			}
			return []string{"-A", target}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-A", target}
			},
		},
	},
	// ── snmpwalk — SNMP enumeration ───────────────────────────────────────────
	{
		Name:        "snmpwalk",
		Phase:       3,
		Timeout:     120,
		DomainOnly:  false,
		InstallHint: "sudo apt install -y snmp",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			// Only run if SNMP port is open
			for _, p := range ctx.OpenPorts {
				if p == 161 || p == 162 {
					return []string{"-v2c", "-c", "public", target}
				}
			}
			return []string{"-v2c", "-c", "public", target, "system"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-v1", "-c", "public", target}
			},
		},
	},
	// ── dorks_hunter — Google dorking automation ──────────────────────────────
	{
		Name:        "dorks_hunter",
		Phase:       1,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "pip3 install dorks-hunter --break-system-packages || git clone https://github.com/six2dez/dorks_hunter /opt/dorks_hunter && pip3 install -r /opt/dorks_hunter/requirements.txt --break-system-packages && sudo ln -sf /opt/dorks_hunter/dorks_hunter.py /usr/local/bin/dorks_hunter",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target, "-o", "/tmp/cybermind_dorks.txt"}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"-d", target}
			},
		},
	},
	// ── analyticsrelationships — Google Analytics subdomain discovery ──────────
	{
		Name:        "analyticsrelationships",
		Phase:       2,
		Timeout:     120,
		DomainOnly:  true,
		InstallHint: "go install github.com/Josue87/analyticsrelationships@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			return []string{"-d", target}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"--domain", target}
			},
		},
	},
	// ── gitleaks — git secret detection in repos ──────────────────────────────
	{
		Name:        "gitleaks",
		Phase:       2,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://github.com/" + target
			}
			return []string{
				"detect",
				"--source", u,
				"--report-format", "json",
				"--report-path", "/tmp/cybermind_gitleaks.json",
				"--no-banner",
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				return []string{"detect", "--source", ".", "--no-banner"}
			},
		},
	},
	// ── testssl — comprehensive TLS testing ───────────────────────────────────
	{
		Name:        "testssl",
		Phase:       4,
		Timeout:     300,
		DomainOnly:  true,
		InstallHint: "sudo apt install -y testssl.sh || git clone https://github.com/drwetter/testssl.sh /opt/testssl && sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl",
		BuildArgs: func(target string, ctx *ReconContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"--quiet",
				"--color", "0",
				"--jsonfile", "/tmp/cybermind_testssl.json",
				u,
			}
		},
		FallbackArgs: []func(target string, ctx *ReconContext) []string{
			func(target string, ctx *ReconContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"--quiet", "--color", "0", u}
			},
		},
	},
}

func init() {
	// Append all tier tools to the main registry at startup
	toolRegistry = append(toolRegistry, tier1Tools...)
}
