package omega

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"cybermind-cli/api"
	"cybermind-cli/utils"

	"github.com/charmbracelet/lipgloss"
)

var (
cyan   = lipgloss.Color("#00FFFF")
green  = lipgloss.Color("#00FF00")
red    = lipgloss.Color("#FF4444")
yellow = lipgloss.Color("#FFD700")
purple = lipgloss.Color("#8A2BE2")
dim    = lipgloss.Color("#777777")
orange = lipgloss.Color("#FF6600")
)


// ─── System Resource Check ────────────────────────────────────────────────────

// SystemResources holds current system resource info
type SystemResources struct {
RAMTotalMB  int
RAMFreeMB   int
DiskFreeMB  int
CPUCores    int
Sufficient  bool
Warnings    []string
}

// CheckSystemResources checks if system has enough resources for planning mode
func CheckSystemResources() SystemResources {
res := SystemResources{
CPUCores: runtime.NumCPU(),
Warnings: []string{},
}

// Check RAM via /proc/meminfo on Linux
if runtime.GOOS == "linux" {
data, err := os.ReadFile("/proc/meminfo")
if err == nil {
lines := strings.Split(string(data), "\n")
for _, line := range lines {
var key string
var val int
if _, err := fmt.Sscanf(line, "%s %d", &key, &val); err == nil {
switch key {
case "MemTotal:":
res.RAMTotalMB = val / 1024
case "MemAvailable:":
res.RAMFreeMB = val / 1024
}
}
}
}
// Check disk space
out, err := exec.Command("df", "-m", "/tmp").Output()
if err == nil {
lines := strings.Split(string(out), "\n")
if len(lines) > 1 {
fields := strings.Fields(lines[1])
if len(fields) >= 4 {
fmt.Sscanf(fields[3], "%d", &res.DiskFreeMB)
}
}
}
}

// Minimum requirements
if res.RAMFreeMB > 0 && res.RAMFreeMB < 512 {
res.Warnings = append(res.Warnings, fmt.Sprintf("Low RAM: %dMB free (recommend 1GB+)", res.RAMFreeMB))
}
if res.DiskFreeMB > 0 && res.DiskFreeMB < 1024 {
res.Warnings = append(res.Warnings, fmt.Sprintf("Low disk: %dMB free in /tmp (recommend 2GB+)", res.DiskFreeMB))
}
if res.CPUCores < 2 {
res.Warnings = append(res.Warnings, "Single CPU core detected — tools will run slower")
}

res.Sufficient = len(res.Warnings) == 0 || (res.RAMFreeMB == 0) // if we can't read, assume OK
return res
}


// ─── OMEGA Doctor — Auto-install all tools before planning ───────────────────

// OmegaToolEntry defines a tool for OMEGA doctor check
type OmegaToolEntry struct {
Name        string
Mode        string
Install     string
IsGo        bool
IsCargo     bool
IsPip       bool
IsGit       bool
GitURL      string
GitDir      string
MainScript  string
}

// GetOmegaToolList returns the complete tool list for all modes
func GetOmegaToolList() []OmegaToolEntry {
return []OmegaToolEntry{
// ── Recon Phase 1 — Passive OSINT (Linux preinstalled) ──────────────
{"whois", "recon", "sudo apt install -y whois", false, false, false, false, "", "", ""},
{"theHarvester", "recon", "sudo apt install -y theharvester", false, false, false, false, "", "", ""},
{"dig", "recon", "sudo apt install -y dnsutils", false, false, false, false, "", "", ""},
{"curl", "recon", "sudo apt install -y curl", false, false, false, false, "", "", ""},
{"wget", "recon", "sudo apt install -y wget", false, false, false, false, "", "", ""},
// ── Recon Phase 2 — Subdomain Enum ──────────────────────────────────
{"subfinder", "recon", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", true, false, false, false, "", "", ""},
{"amass", "recon", "sudo apt install -y amass", false, false, false, false, "", "", ""},
{"dnsx", "recon", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", true, false, false, false, "", "", ""},
{"reconftw", "recon", "git clone https://github.com/six2dez/reconftw.git /opt/reconftw && cd /opt/reconftw && ./install.sh", false, false, false, true, "https://github.com/six2dez/reconftw.git", "/opt/reconftw", "reconftw.sh"},
// ── Recon Phase 3 — Port Scanning ───────────────────────────────────
{"nmap", "recon", "sudo apt install -y nmap", false, false, false, false, "", "", ""},
{"masscan", "recon", "sudo apt install -y masscan", false, false, false, false, "", "", ""},
{"naabu", "recon", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true, false, false, false, "", "", ""},
{"rustscan", "recon", "cargo install rustscan", false, true, false, false, "", "", ""},
// ── Recon Phase 4 — HTTP Fingerprinting ─────────────────────────────
{"httpx", "recon", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", true, false, false, false, "", "", ""},
{"whatweb", "recon", "sudo apt install -y whatweb", false, false, false, false, "", "", ""},
{"tlsx", "recon", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", true, false, false, false, "", "", ""},
{"wafw00f", "recon", "pip3 install wafw00f --break-system-packages", false, false, true, false, "", "", ""},
// ── Recon Phase 5 — Directory Discovery ─────────────────────────────
{"ffuf", "recon", "sudo apt install -y ffuf", false, false, false, false, "", "", ""},
{"feroxbuster", "recon", "sudo apt install -y feroxbuster", false, false, false, false, "", "", ""},
{"gobuster", "recon", "sudo apt install -y gobuster", false, false, false, false, "", "", ""},
// ── Recon Phase 6 — Vuln Scanning ───────────────────────────────────
{"nuclei", "recon", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", true, false, false, false, "", "", ""},
{"nikto", "recon", "sudo apt install -y nikto", false, false, false, false, "", "", ""},
{"katana", "recon", "go install github.com/projectdiscovery/katana/cmd/katana@latest", true, false, false, false, "", "", ""},
// ── Hunt Phase 1 — URL Collection ───────────────────────────────────
{"gau", "hunt", "go install github.com/lc/gau/v2/cmd/gau@latest", true, false, false, false, "", "", ""},
{"waybackurls", "hunt", "go install github.com/tomnomnom/waybackurls@latest", true, false, false, false, "", "", ""},
{"waymore", "hunt", "pip3 install waymore --break-system-packages", false, false, true, false, "", "", ""},
{"hakrawler", "hunt", "go install github.com/hakluke/hakrawler@latest", true, false, false, false, "", "", ""},
{"urlfinder", "hunt", "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest", true, false, false, false, "", "", ""},
{"httprobe", "hunt", "go install github.com/tomnomnom/httprobe@latest", true, false, false, false, "", "", ""},
// ── Hunt Phase 2 — Deep Crawl ────────────────────────────────────────
{"gospider", "hunt", "go install github.com/jaeles-project/gospider@latest", true, false, false, false, "", "", ""},
{"cariddi", "hunt", "go install github.com/edoardottt/cariddi/cmd/cariddi@latest", true, false, false, false, "", "", ""},
{"subjs", "hunt", "go install github.com/lc/subjs@latest", true, false, false, false, "", "", ""},
{"trufflehog", "hunt", "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin", false, false, false, false, "", "", ""},
{"mantra", "hunt", "go install github.com/MrEmpy/mantra@latest", true, false, false, false, "", "", ""},
// ── Hunt Phase 3 — Parameter Discovery ──────────────────────────────
{"paramspider", "hunt", "git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider && pip3 install -r /opt/paramspider/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/devanshbatham/ParamSpider", "/opt/paramspider", "paramspider.py"},
{"arjun", "hunt", "pip3 install arjun --break-system-packages", false, false, true, false, "", "", ""},
{"x8", "hunt", "Download from https://github.com/Sh1Yo/x8/releases/latest", false, false, false, false, "", "", ""},
{"smuggler", "hunt", "git clone https://github.com/defparam/smuggler /opt/smuggler && pip3 install -r /opt/smuggler/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/defparam/smuggler", "/opt/smuggler", "smuggler.py"},
{"jwt_tool", "hunt", "git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool && pip3 install -r /opt/jwt_tool/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/ticarpi/jwt_tool", "/opt/jwt_tool", "jwt_tool.py"},
{"graphw00f", "hunt", "pip3 install graphw00f --break-system-packages", false, false, true, false, "", "", ""},
// ── Hunt Phase 4 — XSS Hunting ──────────────────────────────────────
{"dalfox", "hunt", "go install github.com/hahwul/dalfox/v2@latest", true, false, false, false, "", "", ""},
{"xsstrike", "hunt", "git clone https://github.com/s0md3v/XSStrike /opt/xsstrike && pip3 install -r /opt/xsstrike/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/s0md3v/XSStrike", "/opt/xsstrike", "xsstrike.py"},
{"kxss", "hunt", "go install github.com/Emoe/kxss@latest", true, false, false, false, "", "", ""},
{"bxss", "hunt", "go install github.com/ethicalhackingplayground/bxss@latest", true, false, false, false, "", "", ""},
{"corsy", "hunt", "git clone https://github.com/s0md3v/Corsy /opt/corsy && pip3 install -r /opt/corsy/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/s0md3v/Corsy", "/opt/corsy", "corsy.py"},
// ── Hunt Phase 5 — Deep Vuln Scan ───────────────────────────────────
{"gf", "hunt", "go install github.com/tomnomnom/gf@latest", true, false, false, false, "", "", ""},
{"ssrfmap", "hunt", "git clone https://github.com/swisskyrepo/SSRFmap /opt/ssrfmap && pip3 install -r /opt/ssrfmap/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/swisskyrepo/SSRFmap", "/opt/ssrfmap", "ssrfmap.py"},
{"tplmap", "hunt", "git clone https://github.com/epinna/tplmap /opt/tplmap && pip3 install -r /opt/tplmap/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/epinna/tplmap", "/opt/tplmap", "tplmap.py"},
{"liffy", "hunt", "git clone https://github.com/mzfr/liffy /opt/liffy && pip3 install -r /opt/liffy/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/mzfr/liffy", "/opt/liffy", "liffy.py"},
{"gopherus", "hunt", "git clone https://github.com/tarunkant/Gopherus /opt/gopherus && pip3 install -r /opt/gopherus/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/tarunkant/Gopherus", "/opt/gopherus", "gopherus.py"},
// ── Abhimanyu Phase 1 — Web Exploitation ────────────────────────────
{"sqlmap", "exploit", "sudo apt install -y sqlmap", false, false, false, false, "", "", ""},
{"commix", "exploit", "sudo apt install -y commix", false, false, false, false, "", "", ""},
{"wpscan", "exploit", "sudo apt install -y wpscan", false, false, false, false, "", "", ""},
{"nosqlmap", "exploit", "git clone https://github.com/codingo/NoSQLMap /opt/nosqlmap && pip3 install -r /opt/nosqlmap/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/codingo/NoSQLMap", "/opt/nosqlmap", "nosqlmap.py"},
{"xxeinjector", "exploit", "git clone https://github.com/enjoiz/XXEinjector /opt/xxeinjector", false, false, false, true, "https://github.com/enjoiz/XXEinjector", "/opt/xxeinjector", "XXEinjector.rb"},
// ── Abhimanyu Phase 2 — Auth Attacks ────────────────────────────────
{"hydra", "exploit", "sudo apt install -y hydra", false, false, false, false, "", "", ""},
{"john", "exploit", "sudo apt install -y john", false, false, false, false, "", "", ""},
{"hashcat", "exploit", "sudo apt install -y hashcat", false, false, false, false, "", "", ""},
{"kerbrute", "exploit", "go install github.com/ropnop/kerbrute@latest", true, false, false, false, "", "", ""},
{"sprayhound", "exploit", "pip3 install sprayhound --break-system-packages", false, false, true, false, "", "", ""},
// ── Abhimanyu Phase 3 — CVE/Exploit Search ──────────────────────────
{"searchsploit", "exploit", "sudo apt install -y exploitdb", false, false, false, false, "", "", ""},
{"msfconsole", "exploit", "sudo apt install -y metasploit-framework", false, false, false, false, "", "", ""},
// ── Abhimanyu Phase 4 — Post-Exploitation ───────────────────────────
{"linpeas", "exploit", "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /opt/linpeas.sh && chmod +x /opt/linpeas.sh && sudo ln -sf /opt/linpeas.sh /usr/local/bin/linpeas", false, false, false, false, "", "", ""},
{"pspy", "exploit", "curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /opt/pspy && chmod +x /opt/pspy && sudo ln -sf /opt/pspy /usr/local/bin/pspy", false, false, false, false, "", "", ""},
{"bloodhound-python", "exploit", "pip3 install bloodhound --break-system-packages && sudo apt install -y neo4j", false, false, true, false, "", "", ""},
{"certipy", "exploit", "pip3 install certipy-ad --break-system-packages", false, false, true, false, "", "", ""},
{"bloodyAD", "exploit", "pip3 install bloodyAD --break-system-packages", false, false, true, false, "", "", ""},
{"ldeep", "exploit", "pip3 install ldeep --break-system-packages", false, false, true, false, "", "", ""},
// ── Abhimanyu Phase 5 — Lateral Movement ────────────────────────────
{"crackmapexec", "exploit", "sudo apt install -y crackmapexec", false, false, false, false, "", "", ""},
{"netexec", "exploit", "pip3 install netexec --break-system-packages", false, false, true, false, "", "", ""},
{"evil-winrm", "exploit", "sudo gem install evil-winrm", false, false, false, false, "", "", ""},
{"impacket-secretsdump", "exploit", "sudo apt install -y python3-impacket", false, false, false, false, "", "", ""},
{"coercer", "exploit", "pip3 install coercer --break-system-packages", false, false, true, false, "", "", ""},
{"mitm6", "exploit", "pip3 install mitm6 --break-system-packages", false, false, true, false, "", "", ""},
{"pywhisker", "exploit", "pip3 install pywhisker --break-system-packages", false, false, true, false, "", "", ""},
// ── Abhimanyu Phase 6 — Persistence + Exfil ─────────────────────────
{"chisel", "exploit", "go install github.com/jpillora/chisel@latest", true, false, false, false, "", "", ""},
{"ligolo-ng", "exploit", "go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest", true, false, false, false, "", "", ""},
{"iodine", "exploit", "sudo apt install -y iodine", false, false, false, false, "", "", ""},
{"donut", "exploit", "pip3 install donut-shellcode --break-system-packages", false, false, true, false, "", "", ""},
{"evilginx2", "exploit", "go install github.com/kgretzky/evilginx2@latest", true, false, false, false, "", "", ""},
// ── Recon Phase 3 — NEW: ZMap ────────────────────────────────────────
{"zmap", "recon", "sudo apt install -y zmap", false, false, false, false, "", "", ""},
// ── Hunt Phase 4 — NEW: BeEF ─────────────────────────────────────────
{"beef-xss", "hunt", "sudo apt install -y beef-xss", false, false, false, false, "", "", ""},
// ── OSINT Deep — Phase 1: Domain/Subdomain ───────────────────────────
{"sublist3r", "osint", "pip3 install sublist3r --break-system-packages", false, false, true, false, "", "", ""},
{"sn0int", "osint", "sudo apt install -y sn0int", false, false, false, false, "", "", ""},
// ── OSINT Deep — Phase 2: Email/Breach ───────────────────────────────
{"holehe", "osint", "pip3 install holehe --break-system-packages", false, false, true, false, "", "", ""},
{"h8mail", "osint", "pip3 install h8mail --break-system-packages", false, false, true, false, "", "", ""},
{"emailfinder", "osint", "pip3 install emailfinder --break-system-packages", false, false, true, false, "", "", ""},
// ── OSINT Deep — Phase 3: Username/People ────────────────────────────
{"sherlock", "osint", "pip3 install sherlock-project --break-system-packages", false, false, true, false, "", "", ""},
{"maigret", "osint", "pip3 install maigret --break-system-packages", false, false, true, false, "", "", ""},
{"socialscan", "osint", "pip3 install socialscan --break-system-packages", false, false, true, false, "", "", ""},
// ── OSINT Deep — Phase 4: Social Media ───────────────────────────────
{"instaloader", "osint", "pip3 install instaloader --break-system-packages", false, false, true, false, "", "", ""},
{"twscrape", "osint", "pip3 install twscrape --break-system-packages", false, false, true, false, "", "", ""},
// ── OSINT Deep — Phase 5: Company Intel ──────────────────────────────
{"spiderfoot", "osint", "pip3 install spiderfoot --break-system-packages", false, false, true, false, "", "", ""},
{"crosslinked", "osint", "pip3 install crosslinked --break-system-packages", false, false, true, false, "", "", ""},
{"ghunt", "osint", "pip3 install ghunt --break-system-packages", false, false, true, false, "", "", ""},
// ── OSINT Deep — Phase 6: Phone ──────────────────────────────────────
{"phoneinfoga", "osint", "go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest", true, false, false, false, "", "", ""},
{"geoiplookup", "osint", "sudo apt install -y geoip-bin", false, false, false, false, "", "", ""},
// ── OSINT Deep — Phase 7: Metadata ───────────────────────────────────
{"metagoofil", "osint", "pip3 install metagoofil --break-system-packages", false, false, true, false, "", "", ""},
// ── OSINT Deep — Phase 8: Dark Web ───────────────────────────────────
{"onionsearch", "osint", "pip3 install onionsearch --break-system-packages", false, false, true, false, "", "", ""},
{"torbot", "osint", "pip3 install torbot --break-system-packages", false, false, true, false, "", "", ""},
// ── RevEng — Phase 1: File ID ────────────────────────────────────────
{"floss", "reveng", "pip3 install floss --break-system-packages", false, false, true, false, "", "", ""},
{"diec", "reveng", "sudo apt install -y detect-it-easy", false, false, false, false, "", "", ""},
// ── RevEng — Phase 2: Static ─────────────────────────────────────────
{"radare2", "reveng", "sudo apt install -y radare2", false, false, false, false, "", "", ""},
{"rizin", "reveng", "sudo apt install -y rizin", false, false, false, false, "", "", ""},
{"checksec", "reveng", "pip3 install checksec.py --break-system-packages", false, false, true, false, "", "", ""},
// ── RevEng — Phase 3: Dynamic ────────────────────────────────────────
{"frida-trace", "reveng", "pip3 install frida-tools --break-system-packages", false, false, true, false, "", "", ""},
// ── RevEng — Phase 4: Vuln Discovery ─────────────────────────────────
{"ROPgadget", "reveng", "pip3 install ROPgadget --break-system-packages", false, false, true, false, "", "", ""},
{"angr", "reveng", "pip3 install angr --break-system-packages", false, false, true, false, "", "", ""},
{"cve-bin-tool", "reveng", "pip3 install cve-bin-tool --break-system-packages", false, false, true, false, "", "", ""},
// ── RevEng — Phase 5: Malware ────────────────────────────────────────
{"yara", "reveng", "sudo apt install -y yara", false, false, false, false, "", "", ""},
{"ssdeep", "reveng", "sudo apt install -y ssdeep", false, false, false, false, "", "", ""},
// ── RevEng — Phase 6: Decompile ──────────────────────────────────────
{"retdec-decompiler", "reveng", "sudo apt install -y retdec", false, false, false, false, "", "", ""},
{"jadx", "reveng", "sudo apt install -y jadx", false, false, false, false, "", "", ""},
{"apktool", "reveng", "sudo apt install -y apktool", false, false, false, false, "", "", ""},
// ── Locate — Level 3: WiFi ───────────────────────────────────────────
{"kismet", "locate", "sudo apt install -y kismet", false, false, false, false, "", "", ""},
// ── Locate — Level 4: Social Geo ─────────────────────────────────────
{"creepy", "locate", "git clone https://github.com/ilektrojohn/creepy /opt/creepy && pip3 install -r /opt/creepy/requirements.txt --break-system-packages", false, false, false, true, "https://github.com/ilektrojohn/creepy", "/opt/creepy", "creepy.py"},
}
}


// ─── OMEGA Doctor — Pre-plan tool check and auto-install ─────────────────────

// OmegaDoctorResult holds the result of the pre-plan doctor check
type OmegaDoctorResult struct {
TotalTools    int
InstalledOK   int
Installed     []string
Missing       []string
Failed        []string
AllInstalled  bool
}

// RunOmegaDoctor checks all tools and auto-installs missing ones
// Returns true if all tools are ready (or best-effort installed)
func RunOmegaDoctor(onStatus func(tool, status, msg string)) OmegaDoctorResult {
tools := GetOmegaToolList()
result := OmegaDoctorResult{TotalTools: len(tools)}

for _, t := range tools {
_, err := exec.LookPath(t.Name)
if err == nil {
result.InstalledOK++
result.Installed = append(result.Installed, t.Name)
if onStatus != nil {
onStatus(t.Name, "ok", "")
}
continue
}

// Missing — try to install
if onStatus != nil {
onStatus(t.Name, "installing", t.Install)
}

installErr := installOmegaTool(t)
if installErr == nil {
// Verify it's now available
if _, verifyErr := exec.LookPath(t.Name); verifyErr == nil {
result.InstalledOK++
result.Installed = append(result.Installed, t.Name)
if onStatus != nil {
onStatus(t.Name, "installed", "")
}
continue
}
}

// Install failed — try alternative approaches
altErr := installOmegaToolAlt(t)
if altErr == nil {
if _, verifyErr := exec.LookPath(t.Name); verifyErr == nil {
result.InstalledOK++
result.Installed = append(result.Installed, t.Name)
if onStatus != nil {
onStatus(t.Name, "installed_alt", "")
}
continue
}
}

// Still missing — mark as failed but continue
result.Missing = append(result.Missing, t.Name)
if onStatus != nil {
onStatus(t.Name, "failed", fmt.Sprintf("install failed: %v", installErr))
}
}

result.AllInstalled = len(result.Missing) == 0
return result
}

// installOmegaTool installs a tool using its primary method
func installOmegaTool(t OmegaToolEntry) error {
homedir, _ := os.UserHomeDir()

if t.IsGo {
// Extract module path from install command
parts := strings.Fields(t.Install)
if len(parts) >= 3 {
cmd := exec.Command("go", "install", parts[2])
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
if err := cmd.Run(); err != nil {
return err
}
// Symlink to /usr/local/bin
for _, gobin := range []string{homedir + "/go/bin/" + t.Name, "/root/go/bin/" + t.Name} {
if _, err := os.Stat(gobin); err == nil {
exec.Command("sudo", "ln", "-sf", gobin, "/usr/local/bin/"+t.Name).Run()
break
}
}
return nil
}
}

if t.IsPip {
// Extract package name from install command (may differ from tool name)
// e.g. "pip3 install wafw00f --break-system-packages" → "wafw00f"
pkgName := t.Name
installParts := strings.Fields(t.Install)
for i, p := range installParts {
if (p == "install") && i+1 < len(installParts) {
candidate := installParts[i+1]
if !strings.HasPrefix(candidate, "-") {
pkgName = candidate
break
}
}
}

// 1. Ensure pipx is available — install it if missing
if _, pipxErr := exec.LookPath("pipx"); pipxErr != nil {
exec.Command("pip3", "install", "pipx", "--break-system-packages", "-q").Run()
exec.Command("python3", "-m", "pipx", "ensurepath").Run()
}

// 2. Try pipx first — isolated venv, no system conflicts (best for modern Kali/Ubuntu)
if _, pipxErr := exec.LookPath("pipx"); pipxErr == nil {
cmd := exec.Command("pipx", "install", pkgName)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
if cmd.Run() == nil {
exec.Command("pipx", "ensurepath").Run()
return nil
}
}

// 3. Fallback: pip3 with --break-system-packages (works on older systems)
cmd := exec.Command("pip3", "install", pkgName, "--break-system-packages", "-q")
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
if cmd.Run() == nil {
return nil
}

// 4. Last resort: pip3 with --user flag
cmd2 := exec.Command("pip3", "install", pkgName, "--user", "-q")
cmd2.Stdout = os.Stdout
cmd2.Stderr = os.Stderr
cmd2.Stdin = nil
return cmd2.Run()
}

if t.IsCargo {
exec.Command("sudo", "apt", "install", "-y", "libssl-dev", "pkg-config", "cargo").Run()
cmd := exec.Command("cargo", "install", t.Name)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
return cmd.Run()
}

if t.IsGit && t.GitURL != "" {
// Clone repo
exec.Command("sudo", "rm", "-rf", t.GitDir).Run()
cloneCmd := exec.Command("git", "clone", "--depth=1", t.GitURL, t.GitDir)
cloneCmd.Stdout = os.Stdout
cloneCmd.Stderr = os.Stderr
cloneCmd.Stdin = nil
if err := cloneCmd.Run(); err != nil {
return err
}
// Install requirements if present
reqFile := t.GitDir + "/requirements.txt"
if _, err := os.Stat(reqFile); err == nil {
// Try pipx inject first, then pip3
if _, pipxErr := exec.LookPath("pipx"); pipxErr == nil {
exec.Command("pip3", "install", "-r", reqFile, "--break-system-packages", "-q").Run()
} else {
exec.Command("pip3", "install", "-r", reqFile, "--break-system-packages", "-q").Run()
}
}
// Create wrapper script
if t.MainScript != "" {
scriptPath := t.GitDir + "/" + t.MainScript
ext := ""
if strings.HasSuffix(t.MainScript, ".py") {
ext = "python3"
} else if strings.HasSuffix(t.MainScript, ".rb") {
ext = "ruby"
} else if strings.HasSuffix(t.MainScript, ".sh") {
ext = "bash"
}
if ext != "" {
wrapper := fmt.Sprintf("#!/bin/bash\n%s %s \"$@\"\n", ext, scriptPath)
wrapperPath := "/usr/local/bin/" + t.Name
teeCmd := exec.Command("sudo", "tee", wrapperPath)
teeCmd.Stdin = strings.NewReader(wrapper)
teeCmd.Run()
exec.Command("sudo", "chmod", "+x", wrapperPath).Run()
}
}
return nil
}

// APT install
cmd := exec.Command("bash", "-c", t.Install)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
return cmd.Run()
}

// installOmegaToolAlt tries alternative installation methods
func installOmegaToolAlt(t OmegaToolEntry) error {
// Try apt as fallback for any tool
aptName := strings.ToLower(t.Name)
cmd := exec.Command("sudo", "apt", "install", "-y", aptName)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = nil
if cmd.Run() == nil {
return nil
}
// Try pip3 as fallback
cmd2 := exec.Command("pip3", "install", aptName, "--break-system-packages", "-q")
cmd2.Stdout = os.Stdout
cmd2.Stderr = os.Stderr
cmd2.Stdin = nil
if cmd2.Run() == nil {
return nil
}
// Try pipx as fallback
cmd3 := exec.Command("pipx", "install", aptName)
cmd3.Stdout = os.Stdout
cmd3.Stderr = os.Stderr
cmd3.Stdin = nil
if cmd3.Run() == nil {
return nil
}
// Try snap as last resort
cmd4 := exec.Command("sudo", "snap", "install", aptName, "--classic")
cmd4.Stdout = os.Stdout
cmd4.Stderr = os.Stderr
cmd4.Stdin = nil
return cmd4.Run()
}


// ─── OMEGA Passive Recon — Deep Target Intelligence ──────────────────────────

// TargetIntel holds all passively gathered intelligence about a target
type TargetIntel struct {
Target      string
DNSIPs      []string
RDNS        string
OpenPorts   []int
WAFDetected bool
WAFVendor   string
TechStack   []string
MXRecords   []string
TXTRecords  []string
NSRecords   []string
HTTPHeaders map[string]string
StatusCode  int
ServerBanner string
ShodanData  map[string]string
OSHint      string
}

// GatherTargetIntel performs deep passive recon on the target
func GatherTargetIntel(target string, onStatus func(step, result string)) TargetIntel {
intel := TargetIntel{
Target:      target,
HTTPHeaders: make(map[string]string),
ShodanData:  make(map[string]string),
}

// 1. DNS resolution
if onStatus != nil { onStatus("DNS resolution", "") }
addrs, err := net.LookupHost(target)
if err == nil && len(addrs) > 0 {
intel.DNSIPs = addrs
if onStatus != nil { onStatus("DNS", strings.Join(addrs, ", ")) }
}

// 2. Reverse DNS
if len(intel.DNSIPs) > 0 {
names, err := net.LookupAddr(intel.DNSIPs[0])
if err == nil && len(names) > 0 {
intel.RDNS = names[0]
}
}

// 3. MX records
if onStatus != nil { onStatus("MX records", "") }
mxs, err := net.LookupMX(target)
if err == nil {
for _, mx := range mxs {
intel.MXRecords = append(intel.MXRecords, mx.Host)
}
if len(intel.MXRecords) > 0 && onStatus != nil {
onStatus("MX", strings.Join(intel.MXRecords, ", "))
}
}

// 4. TXT records (SPF, DMARC, tech hints)
txts, err := net.LookupTXT(target)
if err == nil {
for _, txt := range txts {
intel.TXTRecords = append(intel.TXTRecords, txt)
// Detect tech from TXT
lower := strings.ToLower(txt)
if strings.Contains(lower, "google") { intel.TechStack = append(intel.TechStack, "Google Workspace") }
if strings.Contains(lower, "microsoft") || strings.Contains(lower, "ms=") { intel.TechStack = append(intel.TechStack, "Microsoft 365") }
if strings.Contains(lower, "atlassian") { intel.TechStack = append(intel.TechStack, "Atlassian") }
if strings.Contains(lower, "salesforce") { intel.TechStack = append(intel.TechStack, "Salesforce") }
if strings.Contains(lower, "shopify") { intel.TechStack = append(intel.TechStack, "Shopify") }
if strings.Contains(lower, "aws") { intel.TechStack = append(intel.TechStack, "AWS") }
}
}

// 5. NS records
nss, err := net.LookupNS(target)
if err == nil {
for _, ns := range nss {
intel.NSRecords = append(intel.NSRecords, ns.Host)
// Detect CDN/hosting from NS
lower := strings.ToLower(ns.Host)
if strings.Contains(lower, "cloudflare") { intel.WAFDetected = true; intel.WAFVendor = "Cloudflare" }
if strings.Contains(lower, "akamai") { intel.WAFDetected = true; intel.WAFVendor = "Akamai" }
if strings.Contains(lower, "fastly") { intel.TechStack = append(intel.TechStack, "Fastly CDN") }
if strings.Contains(lower, "awsdns") { intel.TechStack = append(intel.TechStack, "AWS Route53") }
if strings.Contains(lower, "azure") { intel.TechStack = append(intel.TechStack, "Azure DNS") }
}
}

// 6. HTTP banner grab + tech detection
if onStatus != nil { onStatus("HTTP fingerprint", "") }
for _, scheme := range []string{"https", "http"} {
targetURL := fmt.Sprintf("%s://%s", scheme, target)
client := &http.Client{
Timeout: 8 * time.Second,
CheckRedirect: func(req *http.Request, via []*http.Request) error {
if len(via) >= 3 { return http.ErrUseLastResponse }
return nil
},
}
resp, err := client.Get(targetURL)
if err != nil { continue }
resp.Body.Close()

intel.StatusCode = resp.StatusCode
// Capture all headers
for k, v := range resp.Header {
if len(v) > 0 {
intel.HTTPHeaders[strings.ToLower(k)] = v[0]
}
}

// Tech detection from headers
server := resp.Header.Get("Server")
if server != "" {
intel.ServerBanner = server
intel.TechStack = append(intel.TechStack, "Server:"+server)
lower := strings.ToLower(server)
if strings.Contains(lower, "nginx") { intel.TechStack = append(intel.TechStack, "Nginx") }
if strings.Contains(lower, "apache") { intel.TechStack = append(intel.TechStack, "Apache") }
if strings.Contains(lower, "iis") { intel.TechStack = append(intel.TechStack, "IIS"); intel.OSHint = "Windows" }
if strings.Contains(lower, "cloudflare") { intel.WAFDetected = true; intel.WAFVendor = "Cloudflare" }
}
powered := resp.Header.Get("X-Powered-By")
if powered != "" {
intel.TechStack = append(intel.TechStack, "X-Powered-By:"+powered)
lower := strings.ToLower(powered)
if strings.Contains(lower, "php") { intel.TechStack = append(intel.TechStack, "PHP") }
if strings.Contains(lower, "asp.net") { intel.TechStack = append(intel.TechStack, "ASP.NET"); intel.OSHint = "Windows" }
if strings.Contains(lower, "express") { intel.TechStack = append(intel.TechStack, "Node.js/Express") }
}
// WAF detection from headers
if resp.Header.Get("CF-RAY") != "" { intel.WAFDetected = true; intel.WAFVendor = "Cloudflare" }
if resp.Header.Get("X-Sucuri-ID") != "" { intel.WAFDetected = true; intel.WAFVendor = "Sucuri" }
if resp.Header.Get("X-Akamai-Transformed") != "" { intel.WAFDetected = true; intel.WAFVendor = "Akamai" }
if resp.Header.Get("X-CDN") != "" { intel.TechStack = append(intel.TechStack, "CDN:"+resp.Header.Get("X-CDN")) }

if onStatus != nil {
onStatus("HTTP", fmt.Sprintf("Status %d | Server: %s", resp.StatusCode, server))
}
break
}

// 7. Shodan — use real API if key available, else free InternetDB
if onStatus != nil { onStatus("Shodan", "") }
if len(intel.DNSIPs) > 0 {
ip := intel.DNSIPs[0]
if !isPrivateIPOmega(ip) {
// Priority: env var → cached tools_config.json → free InternetDB
shodanAPIKey := os.Getenv("SHODAN_API_KEY")
if shodanAPIKey == "" {
	homedir, _ := os.UserHomeDir()
	if data, err := os.ReadFile(homedir + "/.cybermind/tools_config.json"); err == nil {
		var cfg struct { ShodanAPIKey string `json:"shodan_api_key"` }
		if json.Unmarshal(data, &cfg) == nil && cfg.ShodanAPIKey != "" {
			shodanAPIKey = cfg.ShodanAPIKey
			os.Setenv("SHODAN_API_KEY", shodanAPIKey)
		}
	}
}
shodanClient := &http.Client{Timeout: 10 * time.Second}

var shodanURL string
if shodanAPIKey != "" {
	// Real Shodan API — full data: org, ISP, OS, all services, CVEs
	shodanURL = "https://api.shodan.io/shodan/host/" + ip + "?key=" + shodanAPIKey
	if onStatus != nil { onStatus("Shodan API", "using real API key") }
} else {
	// Free InternetDB — limited but no key needed
	shodanURL = "https://internetdb.shodan.io/" + ip
	if onStatus != nil { onStatus("Shodan InternetDB", "free tier") }
}

shodanResp, err := shodanClient.Get(shodanURL)
if err == nil && shodanResp.StatusCode == 200 {
defer shodanResp.Body.Close()
var body strings.Builder
buf := make([]byte, 32768)
for {
n, readErr := shodanResp.Body.Read(buf)
if n > 0 { body.Write(buf[:n]) }
if readErr != nil { break }
}
raw := body.String()

if shodanAPIKey != "" {
	// Parse full Shodan API response
	// Extract org, isp, os, country
	if org := extractJSONStringOmega(raw, "org"); org != "" {
		intel.ShodanData["org"] = org
		intel.TechStack = append(intel.TechStack, "Org:"+org)
	}
	if isp := extractJSONStringOmega(raw, "isp"); isp != "" {
		intel.ShodanData["isp"] = isp
	}
	if osHint := extractJSONStringOmega(raw, "os"); osHint != "" && intel.OSHint == "" {
		intel.OSHint = osHint
		intel.ShodanData["os"] = osHint
	}
	if country := extractJSONStringOmega(raw, "country_name"); country != "" {
		intel.ShodanData["country"] = country
	}
}

// Parse ports (works for both API and InternetDB)
if ports := extractJSONArrayOmega(raw, "ports"); ports != "" {
intel.ShodanData["ports"] = ports
for _, p := range strings.Split(ports, ",") {
p = strings.TrimSpace(p)
var port int
if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 {
intel.OpenPorts = append(intel.OpenPorts, port)
}
}
}
if vulns := extractJSONArrayOmega(raw, "vulns"); vulns != "" {
intel.ShodanData["vulns"] = vulns
}
if tags := extractJSONArrayOmega(raw, "tags"); tags != "" {
intel.ShodanData["tags"] = tags
if strings.Contains(tags, "cloud") { intel.TechStack = append(intel.TechStack, "Cloud hosted") }
if strings.Contains(tags, "vpn") { intel.TechStack = append(intel.TechStack, "VPN") }
if strings.Contains(tags, "tor") { intel.TechStack = append(intel.TechStack, "Tor exit node") }
if strings.Contains(tags, "self-signed") { intel.TechStack = append(intel.TechStack, "Self-signed cert") }
if strings.Contains(tags, "starttls") { intel.TechStack = append(intel.TechStack, "STARTTLS") }
}
if onStatus != nil {
onStatus("Shodan", fmt.Sprintf("ports=[%s] vulns=[%s] org=[%s]",
	intel.ShodanData["ports"], intel.ShodanData["vulns"], intel.ShodanData["org"]))
}
}
}
}

// Deduplicate tech stack
seen := make(map[string]bool)
var deduped []string
for _, t := range intel.TechStack {
if !seen[t] { seen[t] = true; deduped = append(deduped, t) }
}
intel.TechStack = deduped

return intel
}

func isPrivateIPOmega(ipStr string) bool {
ip := net.ParseIP(ipStr)
if ip == nil { return false }
for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"} {
_, network, err := net.ParseCIDR(cidr)
if err == nil && network.Contains(ip) { return true }
}
return false
}

func extractJSONArrayOmega(jsonStr, key string) string {
search := `"` + key + `":`
idx := strings.Index(jsonStr, search)
if idx < 0 { return "" }
start := strings.Index(jsonStr[idx:], "[")
if start < 0 { return "" }
start += idx
end := strings.Index(jsonStr[start:], "]")
if end < 0 { return "" }
inner := strings.ReplaceAll(jsonStr[start+1:start+end], `"`, "")
return strings.TrimSpace(inner)
}

// extractJSONStringOmega extracts a string value from JSON by key
func extractJSONStringOmega(jsonStr, key string) string {
search := `"` + key + `":`
idx := strings.Index(jsonStr, search)
if idx < 0 { return "" }
rest := jsonStr[idx+len(search):]
rest = strings.TrimSpace(rest)
if len(rest) == 0 { return "" }
if rest[0] == '"' {
	end := strings.Index(rest[1:], `"`)
	if end < 0 { return "" }
	return rest[1 : end+1]
}
// null or number
if strings.HasPrefix(rest, "null") { return "" }
end := strings.IndexAny(rest, ",}\n")
if end < 0 { return strings.TrimSpace(rest) }
return strings.TrimSpace(rest[:end])
}


// ─── OMEGA Plan Display ───────────────────────────────────────────────────────

// DisplayPlan renders the OMEGA attack plan to terminal
func DisplayPlan(plan *api.OmegaPlan, target string) {
s := func(color lipgloss.Color, text string) string {
return lipgloss.NewStyle().Foreground(color).Render(text)
}
bold := func(color lipgloss.Color, text string) string {
return lipgloss.NewStyle().Bold(true).Foreground(color).Render(text)
}

fmt.Println()
fmt.Println(bold(cyan, "  ╔══════════════════════════════════════════════════════════╗"))
fmt.Println(bold(cyan, "  ║          OMEGA ATTACK PLAN — "+target))
fmt.Println(bold(cyan, "  ╚══════════════════════════════════════════════════════════╝"))
fmt.Println()

// Risk level with color
riskColor := green
switch strings.ToLower(plan.RiskLevel) {
case "critical": riskColor = red
case "high":     riskColor = orange
case "medium":   riskColor = yellow
}

fmt.Println(s(dim, "  Target Type:    ") + bold(cyan, plan.TargetType+" / "+plan.TargetSubtype))
fmt.Println(s(dim, "  Risk Level:     ") + bold(riskColor, strings.ToUpper(plan.RiskLevel)))
fmt.Println(s(dim, "  WAF Strategy:   ") + s(yellow, plan.WAFStrategy))
fmt.Println(s(dim, "  Est. Time:      ") + s(cyan, fmt.Sprintf("%d minutes", plan.EstimatedTotalMinutes)))

if len(plan.CVEsPredetected) > 0 {
fmt.Println(s(dim, "  CVEs Found:     ") + bold(red, strings.Join(plan.CVEsPredetected, ", ")))
}
if len(plan.AttackVectors) > 0 {
fmt.Println(s(dim, "  Attack Vectors: ") + s(orange, strings.Join(plan.AttackVectors, ", ")))
}
if plan.Notes != "" {
fmt.Println(s(dim, "  Notes:          ") + s(lipgloss.Color("#E0E0E0"), plan.Notes))
}

fmt.Println()
fmt.Println(bold(purple, "  PHASES:"))
fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))

for _, phase := range plan.Phases {
fmt.Println()
fmt.Printf("%s %s\n",
bold(cyan, fmt.Sprintf("  Phase %d:", phase.Phase)),
bold(lipgloss.Color("#E0E0E0"), phase.Name))
fmt.Println(s(dim, "    Goal:    ") + s(lipgloss.Color("#E0E0E0"), phase.Goal))
fmt.Println(s(dim, "    Time:    ") + s(yellow, fmt.Sprintf("~%d min", phase.EstimatedMinutes)))
fmt.Println(s(dim, "    Tools:   ") + s(green, strings.Join(phase.ToolsRun, ", ")))
if len(phase.ToolsSkip) > 0 {
fmt.Println(s(dim, "    Skip:    ") + s(red, strings.Join(phase.ToolsSkip, ", ")))
}
if phase.Why != "" {
fmt.Println(s(dim, "    Why:     ") + s(lipgloss.Color("#AAAAAA"), phase.Why))
}
if phase.ExpectedFindings != "" {
fmt.Println(s(dim, "    Expect:  ") + s(orange, phase.ExpectedFindings))
}
// Show specific commands that will run
if len(phase.ToolsRun) > 0 {
fmt.Println(s(dim, "    Commands:"))
for _, tool := range phase.ToolsRun {
cmd := getToolCommand(tool, target)
if cmd != "" {
fmt.Println(s(lipgloss.Color("#555555"), "      $ "+cmd))
}
}
}
}

fmt.Println()
fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))

// ── ALWAYS show Abhimanyu as the final guaranteed phase ──────────────
fmt.Println()
fmt.Println(bold(red, "  ⚔️  ABHIMANYU MODE — GUARANTEED FINAL PHASE:"))
fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))
fmt.Println()
fmt.Println(s(dim, "  Abhimanyu runs AUTOMATICALLY after hunt, regardless of bug count."))
fmt.Println(s(dim, "  It installs its own tools and may find what hunt missed."))
fmt.Println()
abhimanyuPhases := []struct{ phase, tools, desc string }{
{"Phase 1 — Web Exploitation", "sqlmap, commix, nikto, tplmap, nosqlmap, xxeinjector", "SQLi, RCE, CMDi, SSTI, XXE, NoSQL injection"},
{"Phase 2 — Auth Attacks",     "hydra, john, hashcat, kerbrute, sprayhound",            "Brute force, hash cracking, Kerberos attacks"},
{"Phase 3 — CVE Search",       "searchsploit, msfconsole",                              "Known CVEs for detected services"},
{"Phase 4 — Post-Exploit",     "linpeas, pspy, bloodhound, certipy, bloodyAD",          "Privilege escalation, AD attacks (if shell obtained)"},
{"Phase 5 — Lateral Movement", "crackmapexec, netexec, evil-winrm, impacket",           "SMB, WinRM, LDAP lateral movement"},
{"Phase 6 — Persistence",      "chisel, ligolo-ng, evilginx2, donut",                  "Tunneling, phishing, shellcode (if needed)"},
}
for _, p := range abhimanyuPhases {
fmt.Println(bold(red, "  "+p.phase+":"))
fmt.Println(s(orange, "    Tools: "+p.tools))
fmt.Println(s(dim, "    → "+p.desc))
fmt.Println()
}

fmt.Println()
fmt.Println(bold(lipgloss.Color("#FF6600"), "  🧠 HACKER BRAIN — 6-ANGLE ATTACK ANALYSIS:"))
fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))
fmt.Println()
angles := []struct{ icon, angle, desc string }{
{"🔍", "Recon Angle", "Map full attack surface: subdomains, endpoints, params, JS files"},
{"🔐", "Auth Angle", "Test login flows, JWT, OAuth, session fixation, password reset"},
{"💉", "Injection Angle", "SQLi, XSS, SSTI, XXE, SSRF on all input vectors"},
{"🔑", "Access Control", "IDOR, privilege escalation, horizontal/vertical auth bypass"},
{"⚙️", "Business Logic", "Race conditions, price manipulation, workflow bypass"},
{"🌐", "Infrastructure", "Exposed APIs, misconfigs, CVEs, subdomain takeover"},
}
for _, a := range angles {
fmt.Println(s(cyan, fmt.Sprintf("  %s %s:", a.icon, a.angle)))
fmt.Println(s(lipgloss.Color("#AAAAAA"), "    → "+a.desc))
fmt.Println()
}
}

// getToolCommand returns a representative command string for a given tool and target.
func getToolCommand(tool, target string) string {
cmds := map[string]string{
"subfinder":   "subfinder -d " + target + " -silent -all",
"amass":       "amass enum -passive -d " + target,
"reconftw":    "reconftw.sh -d " + target + " -s",
"nmap":        "nmap -sV -sC -T4 --top-ports 1000 " + target,
"rustscan":    "rustscan -a " + target + " --ulimit 5000 -- -sV",
"httpx":       "httpx -l subdomains.txt -title -tech-detect -status-code",
"nuclei":      "nuclei -u " + target + " -t cves/ -t exposures/ -severity critical,high,medium",
"dalfox":      "dalfox url https://" + target + " --deep-domxss",
"sqlmap":      "sqlmap -u https://" + target + " --batch --level=3 --risk=2",
"gau":         "gau " + target + " | tee urls.txt",
"waybackurls": "waybackurls " + target + " | tee wayback.txt",
"paramspider": "paramspider -d " + target,
"ffuf":        "ffuf -u https://" + target + "/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
"katana":      "katana -u https://" + target + " -d 5 -jc",
"trufflehog":  "trufflehog git https://github.com/" + target,
"shodan":      "shodan host " + target,
}
if cmd, ok := cmds[tool]; ok {
return cmd
}
return ""
}

// DisplayPlanRaw renders a raw text plan (when JSON parsing failed)
func DisplayPlanRaw(raw string) {
fmt.Println()
fmt.Println(lipgloss.NewStyle().Bold(true).Foreground(cyan).Render("  📋 OMEGA ATTACK PLAN"))
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("  "+strings.Repeat("─", 60)))
fmt.Println()
fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0")).MarginLeft(2).Render(utils.StripMarkdown(raw)))
fmt.Println()
}

// SavePlanToFile saves the OMEGA plan to a JSON file
func SavePlanToFile(plan *api.OmegaPlan, target string) (string, error) {
ts := time.Now().Format("2006-01-02_15-04-05")
safeTarget := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), "/", "_")
filename := fmt.Sprintf("omega_plan_%s_%s.json", safeTarget, ts)

type planFile struct {
Target    string         `json:"target"`
CreatedAt string         `json:"created_at"`
Status    string         `json:"status"`
Plan      *api.OmegaPlan `json:"plan"`
}

data, err := json.MarshalIndent(planFile{
Target:    target,
CreatedAt: time.Now().UTC().Format(time.RFC3339),
Status:    "pending",
Plan:      plan,
}, "", "  ")
if err != nil {
return "", err
}
return filename, os.WriteFile(filename, data, 0644)
}


// ─── Tech-Aware Tool Selection ────────────────────────────────────────────────

// ToolSelection holds the recommended tools for each phase based on target intel.
type ToolSelection struct {
	ReconTools          []string // tools to prioritize in recon phase
	HuntTools           []string // tools to prioritize in hunt phase
	ExploitTools        []string // tools to prioritize in Abhimanyu phase
	SkipTools           []string // tools to skip (not relevant for this target)
	VulnFocus           string   // primary vuln focus: sqli|xss|rce|ssrf|all
	Notes               []string // human-readable notes about why tools were selected
	AbhimanyuTools      []string // specific Abhimanyu tools for this target
	AbhimanyuVulnFocus  string   // Abhimanyu vuln focus: sqli|xss|rce|auth|all
	AbhimanyuPhases     []AbhimanyuPhaseInfo // per-phase Abhimanyu plan
}

// AbhimanyuPhaseInfo describes what Abhimanyu will do in each phase for this target
type AbhimanyuPhaseInfo struct {
	Phase       int
	Name        string
	Tools       []string
	Why         string
	ExpectedOut string
}

// SelectToolsByIntel returns a target-specific tool selection based on gathered intelligence.
// This is the core of "intelligent planning" — instead of running all 120+ tools,
// we select the most relevant ones based on what we know about the target.
func SelectToolsByIntel(intel TargetIntel) ToolSelection {
	sel := ToolSelection{
		VulnFocus: "all",
	}

	// ── Abhimanyu exploit tools — always populated based on tech ─────────
	// These are the specific Abhimanyu tools that will run in the final phase
	// based on what we know about the target BEFORE scanning starts.
	sel.AbhimanyuTools = selectAbhimanyuTools(intel)
	sel.AbhimanyuVulnFocus = selectAbhimanyuFocus(intel)
	// Build per-phase Abhimanyu plan after tools are selected
	defer func() {
		sel.AbhimanyuPhases = buildAbhimanyuPhases(intel, sel)
	}()

	techStr := strings.ToLower(strings.Join(intel.TechStack, " "))
	serverStr := strings.ToLower(intel.ServerBanner)

	// ── WordPress detection ───────────────────────────────────────────────
	if strings.Contains(techStr, "wordpress") || strings.Contains(techStr, "wp-") {
		sel.ReconTools = append(sel.ReconTools, "wpscan", "nuclei")
		sel.HuntTools = append(sel.HuntTools, "wpscan", "nuclei", "paramspider", "dalfox")
		sel.ExploitTools = append(sel.ExploitTools, "wpscan", "sqlmap", "commix")
		sel.VulnFocus = "sqli,xss,rce"
		sel.Notes = append(sel.Notes, "WordPress detected → wpscan, xmlrpc attacks, plugin CVEs")
		// Skip tools not relevant for WordPress
		sel.SkipTools = append(sel.SkipTools, "graphw00f", "kerbrute", "nosqlmap")
	}

	// ── GraphQL detection ─────────────────────────────────────────────────
	if strings.Contains(techStr, "graphql") || strings.Contains(techStr, "apollo") {
		sel.HuntTools = append(sel.HuntTools, "graphw00f", "nuclei", "jwt_tool")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "commix")
		sel.VulnFocus = "idor,ssrf,injection"
		sel.Notes = append(sel.Notes, "GraphQL detected → introspection, batching attacks, IDOR")
		sel.SkipTools = append(sel.SkipTools, "wpscan", "kerbrute")
	}

	// ── Node.js / Express detection ───────────────────────────────────────
	if strings.Contains(techStr, "node") || strings.Contains(techStr, "express") ||
		strings.Contains(techStr, "x-powered-by:express") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "dalfox", "smuggler", "jwt_tool")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "commix")
		sel.VulnFocus = "ssrf,prototype,xss"
		sel.Notes = append(sel.Notes, "Node.js/Express detected → prototype pollution, SSRF, JWT attacks")
		sel.SkipTools = append(sel.SkipTools, "wpscan", "kerbrute", "nosqlmap")
	}

	// ── PHP detection ─────────────────────────────────────────────────────
	if strings.Contains(techStr, "php") || strings.Contains(serverStr, "php") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "dalfox", "paramspider", "tplmap")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "commix", "tplmap")
		sel.VulnFocus = "sqli,lfi,rce"
		sel.Notes = append(sel.Notes, "PHP detected → SQLi, LFI, RCE via file inclusion, SSTI")
	}

	// ── ASP.NET / IIS detection ───────────────────────────────────────────
	if strings.Contains(techStr, "asp.net") || strings.Contains(techStr, "iis") ||
		strings.Contains(serverStr, "iis") || strings.Contains(techStr, "x-powered-by:asp.net") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "smuggler", "jwt_tool")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "commix")
		sel.VulnFocus = "sqli,xxe,deserialization"
		sel.Notes = append(sel.Notes, "ASP.NET/IIS detected → SQLi, XXE, .NET deserialization, ViewState")
		sel.SkipTools = append(sel.SkipTools, "wpscan", "kerbrute", "nosqlmap")
	}

	// ── Java / Spring / Tomcat detection ─────────────────────────────────
	if strings.Contains(techStr, "java") || strings.Contains(techStr, "spring") ||
		strings.Contains(techStr, "tomcat") || strings.Contains(serverStr, "tomcat") ||
		strings.Contains(serverStr, "jetty") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "smuggler", "jwt_tool")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "commix")
		sel.VulnFocus = "deserialization,ssrf,rce"
		sel.Notes = append(sel.Notes, "Java/Spring detected → Log4Shell, deserialization, SSRF, Spring4Shell")
		sel.SkipTools = append(sel.SkipTools, "wpscan", "nosqlmap")
	}

	// ── Django / Python detection ─────────────────────────────────────────
	if strings.Contains(techStr, "django") || strings.Contains(techStr, "python") ||
		strings.Contains(techStr, "flask") || strings.Contains(techStr, "fastapi") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "tplmap", "dalfox", "jwt_tool")
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap", "tplmap", "commix")
		sel.VulnFocus = "ssti,ssrf,sqli"
		sel.Notes = append(sel.Notes, "Django/Python detected → SSTI (Jinja2), SSRF, SQLi")
		sel.SkipTools = append(sel.SkipTools, "wpscan", "kerbrute")
	}

	// ── MongoDB / NoSQL detection ─────────────────────────────────────────
	if strings.Contains(techStr, "mongodb") || strings.Contains(techStr, "nosql") ||
		containsPort(intel.OpenPorts, 27017) {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "nosqlmap")
		sel.ExploitTools = append(sel.ExploitTools, "nosqlmap")
		sel.Notes = append(sel.Notes, "MongoDB/NoSQL detected → NoSQL injection, auth bypass")
	}

	// ── MySQL / PostgreSQL detection ──────────────────────────────────────
	if containsPort(intel.OpenPorts, 3306) || containsPort(intel.OpenPorts, 5432) ||
		strings.Contains(techStr, "mysql") || strings.Contains(techStr, "postgresql") {
		sel.ExploitTools = append(sel.ExploitTools, "sqlmap")
		sel.Notes = append(sel.Notes, "Database port open → sqlmap with direct DB connection")
	}

	// ── SSH detection ─────────────────────────────────────────────────────
	if containsPort(intel.OpenPorts, 22) {
		sel.ExploitTools = append(sel.ExploitTools, "hydra")
		sel.Notes = append(sel.Notes, "SSH port 22 open → hydra brute force, key enumeration")
	}

	// ── SMB / Windows detection ───────────────────────────────────────────
	if containsPort(intel.OpenPorts, 445) || containsPort(intel.OpenPorts, 139) ||
		strings.Contains(techStr, "windows") || intel.OSHint == "Windows" {
		sel.ExploitTools = append(sel.ExploitTools, "crackmapexec", "impacket-secretsdump")
		sel.Notes = append(sel.Notes, "SMB/Windows detected → crackmapexec, pass-the-hash, secretsdump")
	}

	// ── Cloudflare WAF ────────────────────────────────────────────────────
	if intel.WAFDetected && strings.Contains(strings.ToLower(intel.WAFVendor), "cloudflare") {
		sel.Notes = append(sel.Notes, "Cloudflare WAF → stealth mode, rate limiting, WAF bypass payloads")
		// Add WAF bypass tools
		sel.HuntTools = append(sel.HuntTools, "dalfox", "nuclei")
	}

	// ── AWS / Cloud detection ─────────────────────────────────────────────
	if strings.Contains(techStr, "aws") || strings.Contains(techStr, "amazon") ||
		strings.Contains(techStr, "s3") || strings.Contains(techStr, "cloudfront") {
		sel.HuntTools = append(sel.HuntTools, "nuclei", "ssrfmap")
		sel.Notes = append(sel.Notes, "AWS detected → SSRF to metadata (169.254.169.254), S3 bucket misconfig")
	}

	// ── Shodan CVEs ───────────────────────────────────────────────────────
	if vulns, ok := intel.ShodanData["vulns"]; ok && vulns != "" {
		sel.Notes = append(sel.Notes, fmt.Sprintf("Shodan CVEs detected: %s → run searchsploit + nuclei CVE templates", vulns))
		sel.ExploitTools = append(sel.ExploitTools, "searchsploit")
	}

	// ── Default: if no specific tech detected, run full arsenal ──────────
	if len(sel.HuntTools) == 0 {
		sel.VulnFocus = "all"
		sel.Notes = append(sel.Notes, "No specific tech detected — running full tool arsenal")
	}

	// Deduplicate tool lists
	sel.ReconTools = deduplicateTools(sel.ReconTools)
	sel.HuntTools = deduplicateTools(sel.HuntTools)
	sel.ExploitTools = deduplicateTools(sel.ExploitTools)
	sel.SkipTools = deduplicateTools(sel.SkipTools)

	return sel
}

// selectAbhimanyuTools returns the specific Abhimanyu tools for this target
// based on pre-scan intelligence. This makes every plan unique.
func selectAbhimanyuTools(intel TargetIntel) []string {
	techStr := strings.ToLower(strings.Join(intel.TechStack, " "))
	var tools []string

	// Web exploitation tools — based on tech stack
	if strings.Contains(techStr, "php") || strings.Contains(techStr, "mysql") ||
		strings.Contains(techStr, "wordpress") || strings.Contains(techStr, "drupal") {
		tools = append(tools, "sqlmap", "commix")
	}
	if strings.Contains(techStr, "django") || strings.Contains(techStr, "flask") ||
		strings.Contains(techStr, "jinja") || strings.Contains(techStr, "twig") {
		tools = append(tools, "tplmap", "commix")
	}
	if strings.Contains(techStr, "mongodb") || strings.Contains(techStr, "nosql") {
		tools = append(tools, "nosqlmap")
	}
	if strings.Contains(techStr, "wordpress") {
		tools = append(tools, "wpscan")
	}
	if strings.Contains(techStr, "xml") || strings.Contains(techStr, "soap") {
		tools = append(tools, "xxeinjector")
	}

	// Auth tools — based on open ports
	if containsPort(intel.OpenPorts, 22) {
		tools = append(tools, "hydra") // SSH brute force
	}
	if containsPort(intel.OpenPorts, 445) || containsPort(intel.OpenPorts, 139) {
		tools = append(tools, "crackmapexec", "impacket-secretsdump")
	}
	if containsPort(intel.OpenPorts, 3389) {
		tools = append(tools, "hydra") // RDP brute force
	}
	if containsPort(intel.OpenPorts, 3306) {
		tools = append(tools, "hydra") // MySQL brute force
	}

	// CVE tools — always run searchsploit for known tech
	if len(intel.TechStack) > 0 || len(intel.OpenPorts) > 0 {
		tools = append(tools, "searchsploit", "msfconsole")
	}

	// Post-exploit — always include for network targets
	if len(intel.OpenPorts) > 0 {
		tools = append(tools, "linpeas", "pspy")
	}

	// AD tools — for Windows/SMB targets
	if containsPort(intel.OpenPorts, 445) || intel.OSHint == "Windows" ||
		strings.Contains(techStr, "active directory") || strings.Contains(techStr, "kerberos") {
		tools = append(tools, "bloodhound-python", "certipy", "kerbrute", "netexec")
	}

	// Default: if nothing specific, run full web arsenal
	if len(tools) == 0 {
		tools = []string{"sqlmap", "commix", "nikto", "searchsploit", "msfconsole"}
	}

	return deduplicateTools(tools)
}

// selectAbhimanyuFocus returns the primary vuln focus for Abhimanyu
func selectAbhimanyuFocus(intel TargetIntel) string {
	techStr := strings.ToLower(strings.Join(intel.TechStack, " "))

	// Windows/AD → auth attacks first
	if containsPort(intel.OpenPorts, 445) || intel.OSHint == "Windows" {
		return "auth,lateral"
	}
	// PHP/MySQL → SQLi first
	if strings.Contains(techStr, "php") || strings.Contains(techStr, "mysql") {
		return "sqli,rce"
	}
	// Python/Django → SSTI first
	if strings.Contains(techStr, "django") || strings.Contains(techStr, "flask") {
		return "ssti,rce"
	}
	// Java/Spring → deserialization/RCE
	if strings.Contains(techStr, "java") || strings.Contains(techStr, "spring") {
		return "rce,deserialization"
	}
	// Node.js → SSRF/prototype pollution
	if strings.Contains(techStr, "node") || strings.Contains(techStr, "express") {
		return "ssrf,xss"
	}
	// WordPress → plugin vulns
	if strings.Contains(techStr, "wordpress") {
		return "sqli,rce,auth"
	}
	// SSH open → auth brute force
	if containsPort(intel.OpenPorts, 22) {
		return "auth,rce"
	}
	return "all"
}

// buildAbhimanyuPhases creates a detailed per-phase plan for Abhimanyu
func buildAbhimanyuPhases(intel TargetIntel, sel ToolSelection) []AbhimanyuPhaseInfo {
	techStr := strings.ToLower(strings.Join(intel.TechStack, " "))
	isWindows := containsPort(intel.OpenPorts, 445) || intel.OSHint == "Windows"
	hasSSH := containsPort(intel.OpenPorts, 22)
	hasWeb := intel.StatusCode > 0

	phases := []AbhimanyuPhaseInfo{
		{
			Phase: 1,
			Name:  "Web Exploitation",
			Tools: filterTools(sel.AbhimanyuTools, []string{"sqlmap", "commix", "tplmap", "nosqlmap", "xxeinjector", "wpscan", "nikto"}),
			Why:   buildPhase1Why(techStr, hasWeb),
			ExpectedOut: "SQLi dump, RCE shell, SSTI execution, XXE file read",
		},
		{
			Phase: 2,
			Name:  "Auth Attacks",
			Tools: filterTools(sel.AbhimanyuTools, []string{"hydra", "john", "hashcat", "kerbrute", "sprayhound"}),
			Why:   buildPhase2Why(intel.OpenPorts, isWindows),
			ExpectedOut: "Cracked credentials, valid SSH/RDP/SMB login",
		},
		{
			Phase: 3,
			Name:  "CVE / Exploit Search",
			Tools: filterTools(sel.AbhimanyuTools, []string{"searchsploit", "msfconsole"}),
			Why:   fmt.Sprintf("Tech stack: %s | Ports: %v", strings.Join(intel.TechStack[:min3(len(intel.TechStack), 3)], ","), intel.OpenPorts[:min3(len(intel.OpenPorts), 5)]),
			ExpectedOut: "Known CVE exploits, MSF module matches",
		},
		{
			Phase: 4,
			Name:  "Post-Exploitation",
			Tools: filterTools(sel.AbhimanyuTools, []string{"linpeas", "pspy", "bloodhound-python", "certipy", "bloodyAD", "ldeep"}),
			Why:   "Runs only if shell/RCE confirmed in Phase 1-3",
			ExpectedOut: "PrivEsc vectors, SUID binaries, sudo misconfigs, AD attack paths",
		},
		{
			Phase: 5,
			Name:  "Lateral Movement",
			Tools: filterTools(sel.AbhimanyuTools, []string{"crackmapexec", "netexec", "evil-winrm", "impacket-secretsdump", "coercer"}),
			Why:   buildPhase5Why(isWindows, hasSSH),
			ExpectedOut: "NTLM hashes, domain admin access, lateral pivot",
		},
		{
			Phase: 6,
			Name:  "Persistence + Exfil",
			Tools: []string{"chisel", "iodine"},
			Why:   "Tunneling for C2 access after compromise",
			ExpectedOut: "Persistent access, data exfiltration channel",
		},
	}

	// Remove phases with no tools
	var result []AbhimanyuPhaseInfo
	for _, p := range phases {
		if len(p.Tools) > 0 {
			result = append(result, p)
		}
	}
	return result
}

func buildPhase1Why(techStr string, hasWeb bool) string {
	if !hasWeb {
		return "No web service detected — skipping web exploitation"
	}
	reasons := []string{}
	if strings.Contains(techStr, "php") { reasons = append(reasons, "PHP→SQLi/LFI") }
	if strings.Contains(techStr, "django") || strings.Contains(techStr, "flask") { reasons = append(reasons, "Python→SSTI") }
	if strings.Contains(techStr, "wordpress") { reasons = append(reasons, "WordPress→plugin CVEs") }
	if strings.Contains(techStr, "java") { reasons = append(reasons, "Java→deserialization") }
	if len(reasons) == 0 { return "Web service detected — testing all injection vectors" }
	return strings.Join(reasons, " | ")
}

func buildPhase2Why(ports []int, isWindows bool) string {
	reasons := []string{}
	if containsPort(ports, 22) { reasons = append(reasons, "SSH:22 open→hydra brute") }
	if containsPort(ports, 3306) { reasons = append(reasons, "MySQL:3306→hydra") }
	if containsPort(ports, 3389) { reasons = append(reasons, "RDP:3389→hydra") }
	if isWindows { reasons = append(reasons, "Windows→kerbrute+sprayhound") }
	if len(reasons) == 0 { return "Testing default credentials on all services" }
	return strings.Join(reasons, " | ")
}

func buildPhase5Why(isWindows, hasSSH bool) string {
	if isWindows { return "Windows/SMB detected → pass-the-hash, secretsdump, WinRM" }
	if hasSSH { return "SSH available → pivot via SSH tunneling" }
	return "Network lateral movement via discovered credentials"
}

func filterTools(available []string, wanted []string) []string {
	wantedSet := make(map[string]bool)
	for _, w := range wanted { wantedSet[w] = true }
	var result []string
	for _, a := range available {
		if wantedSet[a] { result = append(result, a) }
	}
	// If none of the available tools match, return the wanted list directly
	if len(result) == 0 { return wanted[:min3(len(wanted), 3)] }
	return result
}

func min3(a, b int) int {
	if a < b { return a }
	return b
}

// containsPort checks if a port is in the list
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// deduplicateTools removes duplicate tool names
func deduplicateTools(tools []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, t := range tools {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// DisplayToolSelection prints the tech-aware tool selection to terminal
func DisplayToolSelection(sel ToolSelection, target string) {
	s := func(color lipgloss.Color, text string) string {
		return lipgloss.NewStyle().Foreground(color).Render(text)
	}
	b := func(color lipgloss.Color, text string) string {
		return lipgloss.NewStyle().Bold(true).Foreground(color).Render(text)
	}

	fmt.Println()
	fmt.Println(b(cyan, "  🎯 TECH-AWARE TOOL SELECTION — "+target))
	fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 60)))
	fmt.Println()

	if len(sel.Notes) > 0 {
		fmt.Println(b(yellow, "  Intelligence:"))
		for _, note := range sel.Notes {
			fmt.Println(s(lipgloss.Color("#E0E0E0"), "    → "+note))
		}
		fmt.Println()
	}

	if len(sel.ReconTools) > 0 {
		fmt.Println(b(lipgloss.Color("#00CFFF"), "  Recon priority:  ")+s(green, strings.Join(sel.ReconTools, ", ")))
	}
	if len(sel.HuntTools) > 0 {
		fmt.Println(b(lipgloss.Color("#FF6600"), "  Hunt priority:   ")+s(green, strings.Join(sel.HuntTools, ", ")))
	}
	if len(sel.ExploitTools) > 0 {
		fmt.Println(b(red, "  Exploit tools:   ")+s(green, strings.Join(sel.ExploitTools, ", ")))
	}
	if len(sel.SkipTools) > 0 {
		fmt.Println(b(dim, "  Skipping:        ")+s(dim, strings.Join(sel.SkipTools, ", ")+" (not relevant)"))
	}
	fmt.Println(b(purple, "  Vuln focus:      ")+s(lipgloss.Color("#FFD700"), sel.VulnFocus))

	// ── Show Abhimanyu plan ───────────────────────────────────────────────
	if len(sel.AbhimanyuTools) > 0 {
		fmt.Println()
		fmt.Println(b(red, "  ⚔️  ABHIMANYU PLAN (target-specific):"))
		fmt.Println(s(lipgloss.Color("#333333"), "  "+strings.Repeat("─", 50)))
		fmt.Println(b(red, "  Vuln focus: ")+s(lipgloss.Color("#FFD700"), sel.AbhimanyuVulnFocus))
		fmt.Println(b(red, "  Tools:      ")+s(green, strings.Join(sel.AbhimanyuTools, ", ")))
		if len(sel.AbhimanyuPhases) > 0 {
			fmt.Println()
			for _, p := range sel.AbhimanyuPhases {
				fmt.Println(b(red, fmt.Sprintf("  Phase %d — %s:", p.Phase, p.Name)))
				fmt.Println(s(lipgloss.Color("#FF6600"), "    Tools:  "+strings.Join(p.Tools, ", ")))
				fmt.Println(s(dim, "    Why:    "+p.Why))
				fmt.Println(s(lipgloss.Color("#AAAAAA"), "    Expect: "+p.ExpectedOut))
			}
		}
	}
	fmt.Println()
}
