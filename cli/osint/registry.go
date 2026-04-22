package osint

import (
	"fmt"
	"strings"
)

// OSINTToolSpec defines an OSINT tool in the registry.
type OSINTToolSpec struct {
	Name        string
	Phase       int
	Timeout     int
	TargetTypes []string // nil = all; filter by target type
	InstallHint string
	InstallCmd  string
	AltPaths    []string
	UseShell    bool
	ShellCmd    func(target string, ctx *OSINTContext) string
	BuildArgs   func(target string, ctx *OSINTContext) []string
	FallbackArgs []func(target string, ctx *OSINTContext) []string
}

// osintRegistry — full OSINT arsenal, 9 phases.
// Phase 1: Domain/Subdomain Enumeration
// Phase 2: Email OSINT + Breach Hunting
// Phase 3: Username / People / DOX
// Phase 4: Social Media Scraping
// Phase 5: Company / Org Intelligence
// Phase 6: Phone / Telecom OSINT
// Phase 7: Image / Video Forensics
// Phase 8: Dark Web / Paste / Breach
// Phase 9: Network Intelligence
var osintRegistry = []OSINTToolSpec{

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 1 — DOMAIN / SUBDOMAIN ENUMERATION
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "subfinder", Phase: 1, Timeout: 600,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		InstallCmd:  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-d", target, "-all", "-recursive", "-silent",
				"-o", fmt.Sprintf("/tmp/cybermind_osint_%s/subfinder.txt", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target, "-silent"}
			},
		},
	},
	{
		Name: "amass", Phase: 1, Timeout: 1800,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "sudo apt install amass -y",
		InstallCmd:  "sudo apt install amass -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"enum", "-passive", "-d", target,
				"-o", fmt.Sprintf("/tmp/cybermind_osint_%s/amass.txt", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"enum", "-passive", "-d", target}
			},
		},
	},
	{
		Name: "dnsx", Phase: 1, Timeout: 300,
		TargetTypes: []string{"domain", "ip"},
		InstallHint: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		InstallCmd:  "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			args := []string{"-d", target, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-resp", "-silent"}
			if len(ctx.SubdomainsFound) > 0 {
				f := writeTempListOSINT(ctx.SubdomainsFound)
				if f != "" {
					return []string{"-l", f, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp", "-silent"}
				}
			}
			return args
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target, "-a", "-resp", "-silent"}
			},
		},
	},
	{
		Name: "theHarvester", Phase: 1, Timeout: 600,
		TargetTypes: []string{"domain", "company", "email"},
		InstallHint: "sudo apt install theharvester -y",
		InstallCmd:  "sudo apt install theharvester -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-d", target,
				"-b", "google,bing,yahoo,duckduckgo,baidu,certspotter,crtsh,dnsdumpster,hackertarget,otx,rapiddns,urlscan,virustotal",
				"-l", "500",
				"-f", fmt.Sprintf("/tmp/cybermind_osint_%s/harvester", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target, "-b", "google,bing,crtsh", "-l", "200"}
			},
		},
	},
	{
		Name: "sublist3r", Phase: 1, Timeout: 600,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "pip3 install sublist3r --break-system-packages",
		InstallCmd:  "pip3 install sublist3r --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-d", target, "-t", "50",
				"-o", fmt.Sprintf("/tmp/cybermind_osint_%s/sublist3r.txt", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target}
			},
		},
	},
	{
		// crt.sh certificate transparency via curl
		Name: "curl", Phase: 1, Timeout: 60,
		TargetTypes: []string{"domain"},
		InstallHint: "sudo apt install curl -y",
		InstallCmd:  "sudo apt install curl -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-s",
				fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target),
				"-H", "Accept: application/json",
			}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 2 — EMAIL OSINT + BREACH HUNTING
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "holehe", Phase: 2, Timeout: 300,
		TargetTypes: []string{"email", "all"},
		InstallHint: "pip3 install holehe --break-system-packages",
		InstallCmd:  "pip3 install holehe --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.Contains(target, "@") {
				return []string{target}
			}
			if len(ctx.EmailsFound) > 0 {
				return []string{ctx.EmailsFound[0]}
			}
			return nil
		},
	},
	{
		Name: "h8mail", Phase: 2, Timeout: 300,
		TargetTypes: []string{"email", "domain", "all"},
		InstallHint: "pip3 install h8mail --break-system-packages",
		InstallCmd:  "pip3 install h8mail --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			t := target
			if !strings.Contains(t, "@") && len(ctx.EmailsFound) > 0 {
				t = strings.Join(ctx.EmailsFound[:min(5, len(ctx.EmailsFound))], ",")
			}
			return []string{
				"-t", t,
				"--json", fmt.Sprintf("/tmp/cybermind_osint_%s/h8mail.json", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-t", target}
			},
		},
	},
	{
		Name: "emailfinder", Phase: 2, Timeout: 300,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "pip3 install emailfinder --break-system-packages",
		InstallCmd:  "pip3 install emailfinder --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"-d", target}
		},
	},
	{
		// HIBP API — Have I Been Pwned (free, 13B+ records)
		Name: "curl", Phase: 2, Timeout: 30,
		TargetTypes: []string{"email"},
		InstallHint: "sudo apt install curl -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *OSINTContext) string {
			if !strings.Contains(target, "@") {
				return ""
			}
			return fmt.Sprintf(`curl -s -H "hibp-api-key: " -H "User-Agent: CyberMind-OSINT" "https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false" 2>/dev/null || curl -s "https://leakcheck.io/api/public?check=%s" 2>/dev/null`, target, target)
		},
		BuildArgs: func(target string, ctx *OSINTContext) []string { return nil },
	},
	{
		Name: "sn0int", Phase: 2, Timeout: 600,
		TargetTypes: []string{"domain", "email"},
		InstallHint: "sudo apt install sn0int -y",
		InstallCmd:  "sudo apt install sn0int -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"run", "-w", target, "kpcyrd/subdomains-crtsh", "kpcyrd/domains-whois", "kpcyrd/emails-from-domains"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"run", "-w", target, "kpcyrd/subdomains-crtsh"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 3 — USERNAME / PEOPLE / DOX
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "sherlock", Phase: 3, Timeout: 600,
		TargetTypes: []string{"username", "person", "all"},
		InstallHint: "pip3 install sherlock-project --break-system-packages",
		InstallCmd:  "pip3 install sherlock-project --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			if strings.Contains(target, " ") {
				username = strings.ReplaceAll(strings.ToLower(target), " ", "")
			}
			return []string{
				username,
				"--output", fmt.Sprintf("/tmp/cybermind_osint_%s/sherlock.txt", sanitizeForPath(target)),
				"--print-found", "--timeout", "10",
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				username := target
				if strings.Contains(target, "@") {
					username = strings.Split(target, "@")[0]
				}
				return []string{username, "--print-found", "--timeout", "15"}
			},
		},
	},
	{
		Name: "maigret", Phase: 3, Timeout: 900,
		TargetTypes: []string{"username", "person", "all"},
		InstallHint: "pip3 install maigret --break-system-packages",
		InstallCmd:  "pip3 install maigret --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			if strings.Contains(target, " ") {
				username = strings.ReplaceAll(strings.ToLower(target), " ", "")
			}
			return []string{
				username, "--html",
				"--folderoutput", fmt.Sprintf("/tmp/cybermind_osint_%s/maigret/", sanitizeForPath(target)),
				"--timeout", "10", "--retries", "2",
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				username := target
				if strings.Contains(target, "@") {
					username = strings.Split(target, "@")[0]
				}
				return []string{username, "--timeout", "15"}
			},
		},
	},
	{
		Name: "socialscan", Phase: 3, Timeout: 300,
		TargetTypes: []string{"username", "email", "all"},
		InstallHint: "pip3 install socialscan --break-system-packages",
		InstallCmd:  "pip3 install socialscan --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{target, "--json"}
		},
	},
	{
		// WhatsMyName — username check across 600+ sites
		Name: "wmn", Phase: 3, Timeout: 600,
		TargetTypes: []string{"username", "person"},
		InstallHint: "git clone https://github.com/WebBreacher/WhatsMyName /opt/wmn && pip3 install -r /opt/wmn/requirements.txt --break-system-packages && sudo ln -sf /opt/wmn/whats_my_name.py /usr/local/bin/wmn",
		AltPaths:    []string{"/opt/wmn/whats_my_name.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			return []string{"-u", username}
		},
	},
	{
		// RapidAPI Social Media Scanner — handled programmatically in commands.go
		// Returns empty shell command to skip CLI execution
		Name: "rapidapi-social", Phase: 3, Timeout: 30,
		TargetTypes: []string{"username", "person", "email"},
		UseShell:    true,
		ShellCmd: func(target string, ctx *OSINTContext) string {
			// Handled by breach.CheckSocialMediaScanner() in commands.go
			return ""
		},
		BuildArgs: func(target string, ctx *OSINTContext) []string { return nil },
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 4 — SOCIAL MEDIA SCRAPING
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "osintgram", Phase: 4, Timeout: 300,
		TargetTypes: []string{"username", "person", "all"},
		InstallHint: "git clone https://github.com/Datalux/Osintgram /opt/osintgram && pip3 install -r /opt/osintgram/requirements.txt --break-system-packages && sudo ln -sf /opt/osintgram/main.py /usr/local/bin/osintgram",
		AltPaths:    []string{"/opt/osintgram/main.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			return []string{username, "--command", "info,followers,followings,hashtags,captions,tagged,wtagged,photos,stories"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				username := target
				if strings.Contains(target, "@") {
					username = strings.Split(target, "@")[0]
				}
				return []string{username, "--command", "info"}
			},
		},
	},
	{
		Name: "twscrape", Phase: 4, Timeout: 300,
		TargetTypes: []string{"username", "person", "all"},
		InstallHint: "pip3 install twscrape --break-system-packages",
		InstallCmd:  "pip3 install twscrape --break-system-packages",
		UseShell:    true,
		ShellCmd: func(target string, ctx *OSINTContext) string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			return fmt.Sprintf(`python3 -c "import asyncio, twscrape; async def run(): api = twscrape.API(); user = await api.user_by_login('%s'); print(user.json() if user else 'not found'); asyncio.run(run())" 2>/dev/null`, username)
		},
		BuildArgs: func(target string, ctx *OSINTContext) []string { return nil },
	},
	{
		Name: "instaloader", Phase: 4, Timeout: 300,
		TargetTypes: []string{"username", "person"},
		InstallHint: "pip3 install instaloader --break-system-packages",
		InstallCmd:  "pip3 install instaloader --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			username := target
			if strings.Contains(target, "@") {
				username = strings.Split(target, "@")[0]
			}
			return []string{
				"--no-pictures", "--no-videos", "--no-video-thumbnails",
				"--no-geotags", "--no-captions",
				"--dirname-pattern", fmt.Sprintf("/tmp/cybermind_osint_%s/instaloader", sanitizeForPath(target)),
				"--", username,
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				username := target
				if strings.Contains(target, "@") {
					username = strings.Split(target, "@")[0]
				}
				return []string{"--no-pictures", "--", username}
			},
		},
	},
	{
		Name: "photon", Phase: 4, Timeout: 600,
		TargetTypes: []string{"domain", "all"},
		InstallHint: "git clone https://github.com/s0md3v/Photon /opt/photon && pip3 install -r /opt/photon/requirements.txt --break-system-packages && sudo ln -sf /opt/photon/photon.py /usr/local/bin/photon",
		AltPaths:    []string{"/opt/photon/photon.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			u := target
			if !strings.HasPrefix(u, "http") {
				u = "https://" + u
			}
			return []string{
				"-u", u, "--wayback", "--keys", "--secret",
				"-t", "50", "-d", "3",
				"-o", fmt.Sprintf("/tmp/cybermind_osint_%s/photon", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				u := target
				if !strings.HasPrefix(u, "http") {
					u = "https://" + u
				}
				return []string{"-u", u, "--wayback", "-t", "20"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 5 — COMPANY / ORG INTELLIGENCE
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "recon-ng", Phase: 5, Timeout: 600,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "sudo apt install recon-ng -y",
		InstallCmd:  "sudo apt install recon-ng -y",
		UseShell:    true,
		ShellCmd: func(target string, ctx *OSINTContext) string {
			return fmt.Sprintf(`echo "workspaces create %s
db insert domains %s
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-contacts/whois_pocs
run
show hosts
show contacts
exit" | recon-ng 2>/dev/null`, target, target)
		},
		BuildArgs: func(target string, ctx *OSINTContext) []string { return nil },
	},
	{
		Name: "spiderfoot", Phase: 5, Timeout: 1800,
		TargetTypes: []string{"domain", "ip", "company", "email", "all"},
		InstallHint: "pip3 install spiderfoot --break-system-packages",
		InstallCmd:  "pip3 install spiderfoot --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			outFile := fmt.Sprintf("/tmp/cybermind_osint_%s/spiderfoot.json", sanitizeForPath(target))
			return []string{
				"-s", target,
				"-t", "INTERNET_NAME,EMAILADDR,PHONE_NUMBER,USERNAME,SOCIAL_MEDIA,LEAKSITE_CONTENT",
				"-o", "JSON", "-q", "-f", outFile,
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-s", target, "-t", "INTERNET_NAME,EMAILADDR", "-o", "JSON", "-q"}
			},
		},
	},
	{
		Name: "crosslinked", Phase: 5, Timeout: 600,
		TargetTypes: []string{"company", "domain"},
		InstallHint: "pip3 install crosslinked --break-system-packages",
		InstallCmd:  "pip3 install crosslinked --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"-f", "{first}.{last}@" + target, target, "-t", "30"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{target, "-t", "30"}
			},
		},
	},
	{
		Name: "linkedin2username", Phase: 5, Timeout: 600,
		TargetTypes: []string{"company"},
		InstallHint: "git clone https://github.com/initstring/linkedin2username /opt/linkedin2username && pip3 install -r /opt/linkedin2username/requirements.txt --break-system-packages && sudo ln -sf /opt/linkedin2username/linkedin2username.py /usr/local/bin/linkedin2username",
		AltPaths:    []string{"/opt/linkedin2username/linkedin2username.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"-c", target, "-d", target}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-c", target}
			},
		},
	},
	{
		Name: "ghunt", Phase: 5, Timeout: 300,
		TargetTypes: []string{"email"},
		InstallHint: "pip3 install ghunt --break-system-packages",
		InstallCmd:  "pip3 install ghunt --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.Contains(target, "@") {
				return []string{"email", target}
			}
			for _, e := range ctx.EmailsFound {
				if strings.Contains(e, "gmail.com") {
					return []string{"email", e}
				}
			}
			return nil
		},
	},
 

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 6 — PHONE / TELECOM OSINT
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "phoneinfoga", Phase: 6, Timeout: 300,
		TargetTypes: []string{"phone", "all"},
		InstallHint: "go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest",
		InstallCmd:  "go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.HasPrefix(target, "+") || (len(target) >= 10 && isAllDigits(target)) {
				return []string{"scan", "-n", target}
			}
			return nil
		},
	},
	{
		// OSRFramework phonefy — phone number OSINT
		Name: "phonefy", Phase: 6, Timeout: 300,
		TargetTypes: []string{"phone"},
		InstallHint: "pip3 install osrframework --break-system-packages",
		InstallCmd:  "pip3 install osrframework --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.HasPrefix(target, "+") || (len(target) >= 10 && isAllDigits(target)) {
				return []string{"-p", target}
			}
			return nil
		},
	},
	{
		// geoiplookup — IP geolocation
		Name: "geoiplookup", Phase: 6, Timeout: 30,
		TargetTypes: []string{"ip", "domain"},
		InstallHint: "sudo apt install geoip-bin -y",
		InstallCmd:  "sudo apt install geoip-bin -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{target}
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 7 — IMAGE / VIDEO FORENSICS
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "exiftool", Phase: 7, Timeout: 60,
		TargetTypes: []string{"all"},
		InstallHint: "sudo apt install libimage-exiftool-perl -y",
		InstallCmd:  "sudo apt install libimage-exiftool-perl -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			// Only run if target is a file path
			if strings.HasPrefix(target, "/") || strings.HasPrefix(target, "./") {
				return []string{"-a", "-u", "-g1", target}
			}
			return nil
		},
	},
	{
		Name: "metagoofil", Phase: 7, Timeout: 300,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "pip3 install metagoofil --break-system-packages",
		InstallCmd:  "pip3 install metagoofil --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-d", target,
				"-t", "pdf,doc,xls,ppt,docx,xlsx,pptx",
				"-l", "50", "-n", "20",
				"-o", fmt.Sprintf("/tmp/cybermind_osint_%s/metagoofil/", sanitizeForPath(target)),
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target, "-t", "pdf,doc", "-l", "20", "-n", "10"}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 8 — DARK WEB / PASTE / BREACH DATABASES
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "trufflehog", Phase: 8, Timeout: 600,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		InstallCmd:  "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"github", "--org", target, "--json", "--no-update", "--concurrency", "5"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"github", "--org", target, "--json"}
			},
		},
	},
	{
		Name: "gitdorker", Phase: 8, Timeout: 300,
		TargetTypes: []string{"domain", "company"},
		InstallHint: "git clone https://github.com/obheda12/GitDorker /opt/gitdorker && pip3 install -r /opt/gitdorker/requirements.txt --break-system-packages && sudo ln -sf /opt/gitdorker/GitDorker.py /usr/local/bin/gitdorker",
		AltPaths:    []string{"/opt/gitdorker/GitDorker.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"-d", target, "-tf", "/opt/gitdorker/Dorks/alldorksv3", "-p", "3"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-d", target, "-p", "1"}
			},
		},
	},
	{
		Name: "onionsearch", Phase: 8, Timeout: 300,
		TargetTypes: []string{"domain", "company", "all"},
		InstallHint: "pip3 install onionsearch --break-system-packages",
		InstallCmd:  "pip3 install onionsearch --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{target}
		},
	},
	{
		Name: "torbot", Phase: 8, Timeout: 300,
		TargetTypes: []string{"domain"},
		InstallHint: "pip3 install torbot --break-system-packages",
		InstallCmd:  "pip3 install torbot --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.HasSuffix(target, ".onion") {
				return []string{"-m", "crawl", target}
			}
			return nil
		},
	},
	{
		// pwndb — Tor-based leaked credentials search
		Name: "pwndb", Phase: 8, Timeout: 300,
		TargetTypes: []string{"email", "domain"},
		InstallHint: "git clone https://github.com/davidtavarez/pwndb /opt/pwndb && pip3 install -r /opt/pwndb/requirements.txt --break-system-packages && sudo ln -sf /opt/pwndb/pwndb.py /usr/local/bin/pwndb",
		AltPaths:    []string{"/opt/pwndb/pwndb.py"},
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			if strings.Contains(target, "@") {
				return []string{"--target", target, "--output", "json"}
			}
			return []string{"--target", "@" + target, "--output", "json"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"--target", target}
			},
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// PHASE 9 — NETWORK INTELLIGENCE
	// ══════════════════════════════════════════════════════════════════════════

	{
		Name: "nmap", Phase: 9, Timeout: 600,
		TargetTypes: []string{"domain", "ip"},
		InstallHint: "sudo apt install nmap -y",
		InstallCmd:  "sudo apt install nmap -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{
				"-sV", "-sC", "-O",
				"--script", "whois-domain,whois-ip,asn-query,banner,http-title,ssl-cert,dns-brute",
				"-oN", fmt.Sprintf("/tmp/cybermind_osint_%s/nmap.txt", sanitizeForPath(target)),
				target,
			}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"-sV", "--script", "banner,http-title", target}
			},
		},
	},
	{
		Name: "shodan", Phase: 9, Timeout: 120,
		TargetTypes: []string{"domain", "ip", "company"},
		InstallHint: "pip3 install shodan --break-system-packages && shodan init <API_KEY>",
		InstallCmd:  "pip3 install shodan --break-system-packages",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{"host", target}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{"search", "hostname:" + target}
			},
		},
	},
	{
		Name: "whois", Phase: 9, Timeout: 60,
		TargetTypes: []string{"domain", "ip"},
		InstallHint: "sudo apt install whois -y",
		InstallCmd:  "sudo apt install whois -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{target}
		},
	},
	{
		Name: "dig", Phase: 9, Timeout: 60,
		TargetTypes: []string{"domain"},
		InstallHint: "sudo apt install dnsutils -y",
		InstallCmd:  "sudo apt install dnsutils -y",
		BuildArgs: func(target string, ctx *OSINTContext) []string {
			return []string{target, "ANY", "+noall", "+answer"}
		},
		FallbackArgs: []func(target string, ctx *OSINTContext) []string{
			func(target string, ctx *OSINTContext) []string {
				return []string{target, "A", "+short"}
			},
		},
	},
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func sanitizeForPath(s string) string {
	r := strings.NewReplacer("@", "_at_", ".", "_", "+", "", " ", "_", "/", "_", ":", "_")
	return r.Replace(s)
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
