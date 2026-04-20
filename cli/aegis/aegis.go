// Package aegis — CyberMind ↔ Aegis Integration Layer
//
// Aegis is an AI-driven autonomous penetration testing platform (Python).
// This package handles:
//   1. Auto-setup: isolated venv, pip install aegis-cli, all system tools
//   2. Activation: ensure venv is active before any aegis call
//   3. Full integration with OMEGA, Hunt, Abhimanyu, and Recon modes
//   4. Result parsing: reads Aegis SQLite DB and returns structured findings
//
// Architecture:
//   ~/.cybermind/aegis/          ← isolated directory
//   ~/.cybermind/aegis/.venv/    ← Python virtual environment
//   ~/.cybermind/aegis/data/     ← Aegis workspaces + SQLite DBs
//   ~/.cybermind/aegis/config/   ← config.yaml with API keys
//
// Usage from CyberMind:
//   aegis.EnsureInstalled(onStatus)          // one-time setup
//   aegis.RunAuto(target, onLine)            // full autonomous pentest
//   aegis.RunRecon(target, onLine)           // recon only
//   aegis.RunVulnWeb(target, onLine)         // web vuln scan
//   aegis.GetFindings(target)                // read results from DB
package aegis

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// AegisFinding represents a single finding from Aegis SQLite DB
type AegisFinding struct {
	ID          int
	Target      string
	Title       string
	Severity    string // critical, high, medium, low, info
	Category    string
	Description string
	Evidence    string
	URL         string
	CVEs        []string
	Tool        string
	CreatedAt   time.Time
}

// AegisStatus is emitted during setup/run
type AegisStatus struct {
	Step    string
	Message string
	Done    bool
	Error   bool
}

// aegisDir returns the isolated Aegis directory
func aegisDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cybermind", "aegis")
}

// venvPython returns the path to the venv Python binary
func venvPython() string {
	dir := aegisDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, ".venv", "Scripts", "python.exe")
	}
	return filepath.Join(dir, ".venv", "bin", "python3")
}

// venvAegis returns the path to the aegis CLI in the venv
func venvAegis() string {
	dir := aegisDir()
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, ".venv", "Scripts", "aegis.exe")
	}
	return filepath.Join(dir, ".venv", "bin", "aegis")
}

// IsInstalled checks if Aegis is properly installed
func IsInstalled() bool {
	aegisBin := venvAegis()
	_, err := os.Stat(aegisBin)
	return err == nil
}

// EnsureInstalled sets up Aegis in an isolated venv.
// Safe to call multiple times — skips if already installed.
func EnsureInstalled(onStatus func(AegisStatus)) error {
	dir := aegisDir()

	// Step 1: Create directory structure
	onStatus(AegisStatus{Step: "setup", Message: "Creating Aegis directory..."})
	for _, sub := range []string{"", "data", "data/logs", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			return fmt.Errorf("mkdir failed: %w", err)
		}
	}

	// Step 2: Check Python3 availability
	onStatus(AegisStatus{Step: "python", Message: "Checking Python3..."})
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err2 := exec.LookPath("python"); err2 != nil {
			return fmt.Errorf("Python3 not found. Install: sudo apt install -y python3 python3-pip python3-venv")
		}
	}

	// Step 3: Create virtual environment (if not exists)
	venvDir := filepath.Join(dir, ".venv")
	if _, err := os.Stat(venvDir); os.IsNotExist(err) {
		onStatus(AegisStatus{Step: "venv", Message: "Creating Python virtual environment..."})
		py := "python3"
		if _, err := exec.LookPath("python3"); err != nil {
			py = "python"
		}
		cmd := exec.Command(py, "-m", "venv", venvDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("venv creation failed: %w", err)
		}
	}

	// Step 4: Upgrade pip
	onStatus(AegisStatus{Step: "pip", Message: "Upgrading pip..."})
	runInVenv(dir, []string{"-m", "pip", "install", "--upgrade", "pip", "-q"}, nil)

	// Step 5: Install aegis-cli from PyPI
	if !IsInstalled() {
		onStatus(AegisStatus{Step: "install", Message: "Installing aegis-cli from PyPI..."})
		if err := runInVenv(dir, []string{"-m", "pip", "install", "aegis-cli", "-q"}, onStatus); err != nil {
			// Fallback: install from GitHub
			onStatus(AegisStatus{Step: "install", Message: "PyPI failed, trying GitHub..."})
			if err2 := installFromGitHub(dir, onStatus); err2 != nil {
				return fmt.Errorf("aegis install failed: %v | %v", err, err2)
			}
		}
	} else {
		onStatus(AegisStatus{Step: "install", Message: "aegis-cli already installed ✓"})
	}

	// Step 6: Install system tools (apt packages)
	onStatus(AegisStatus{Step: "tools", Message: "Installing system tools (nmap, nuclei, ffuf, sqlmap...)..."})
	installSystemTools(onStatus)

	// Step 7: Write default config.yaml
	configPath := filepath.Join(dir, "config", "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		onStatus(AegisStatus{Step: "config", Message: "Writing default config.yaml..."})
		writeDefaultConfig(configPath)
	}

	// Step 8: Run aegis doctor to verify
	onStatus(AegisStatus{Step: "doctor", Message: "Running aegis doctor..."})
	runAegisCommand(dir, []string{"doctor"}, func(line string) {
		onStatus(AegisStatus{Step: "doctor", Message: line})
	})

	onStatus(AegisStatus{Step: "done", Message: "✓ Aegis fully installed and ready!", Done: true})
	return nil
}

// installFromGitHub clones and installs Aegis from source
func installFromGitHub(dir string, onStatus func(AegisStatus)) error {
	cloneDir := filepath.Join(dir, "aegis-src")
	if _, err := os.Stat(cloneDir); os.IsNotExist(err) {
		onStatus(AegisStatus{Step: "clone", Message: "Cloning Aegis from GitHub..."})
		cmd := exec.Command("git", "clone", "--depth=1", "https://github.com/thecnical/aegis.git", cloneDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	onStatus(AegisStatus{Step: "install", Message: "Installing Aegis from source..."})
	return runInVenvCwd(dir, cloneDir, []string{"-m", "pip", "install", "-e", ".", "-q"}, onStatus)
}

// installSystemTools installs apt packages needed by Aegis
func installSystemTools(onStatus func(AegisStatus)) {
	if runtime.GOOS != "linux" {
		return
	}

	tools := []struct {
		name string
		apt  string
	}{
		{"nmap", "nmap"},
		{"nuclei", ""}, // Go install
		{"ffuf", "ffuf"},
		{"sqlmap", "sqlmap"},
		{"subfinder", ""}, // Go install
		{"theHarvester", "theharvester"},
		{"hydra", "hydra"},
		{"whatweb", "whatweb"},
		{"testssl.sh", "testssl.sh"},
	}

	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err == nil {
			continue // already installed
		}
		if t.apt != "" {
			onStatus(AegisStatus{Step: "tools", Message: fmt.Sprintf("Installing %s...", t.name)})
			exec.Command("sudo", "apt", "install", "-y", t.apt).Run()
		}
	}

	// Go tools
	for _, goTool := range []struct{ name, pkg string }{
		{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"gowitness", "github.com/sensepost/gowitness@latest"},
	} {
		if _, err := exec.LookPath(goTool.name); err != nil {
			onStatus(AegisStatus{Step: "tools", Message: fmt.Sprintf("Installing %s (Go)...", goTool.name)})
			cmd := exec.Command("go", "install", goTool.pkg)
			cmd.Env = append(os.Environ(), "GOPATH="+os.Getenv("HOME")+"/go")
			cmd.Run()
		}
	}
}

// writeDefaultConfig writes a default Aegis config.yaml
func writeDefaultConfig(path string) {
	// Read OpenRouter key from CyberMind config if available
	openrouterKey := os.Getenv("OPENROUTER_KEY")
	if openrouterKey == "" {
		openrouterKey = "CHANGE_ME"
	}

	config := fmt.Sprintf(`general:
  db_path: data/aegis.db
  safe_mode: true
  wordlists_path: data/wordlists

api_keys:
  shodan: CHANGE_ME
  openrouter: %s
  bytez: CHANGE_ME
  nvd: CHANGE_ME

notifications:
  slack_webhook: ""
  discord_webhook: ""

profiles:
  default:
    timeout: 30
    nmap_args: "-sC -sV"
    nuclei_rate: 150
  stealth:
    timeout: 120
    nmap_args: "-sS -T2 --randomize-hosts"
    nuclei_rate: 20
  deep:
    timeout: 90
    nmap_args: "-sC -sV -A -O --script=vuln"
    nuclei_rate: 50
`, openrouterKey)

	os.WriteFile(path, []byte(config), 0600)
}

// ── Run Aegis commands ────────────────────────────────────────────────────────

// RunAuto runs a full autonomous pentest: recon → vuln → AI triage → report
func RunAuto(target string, onLine func(string)) error {
	dir := aegisDir()
	// Add target to scope first
	runAegisCommand(dir, []string{"scope", "add", target, "--kind", "domain"}, onLine)
	// Run full autonomous pentest
	return runAegisCommand(dir, []string{
		"ai", "auto",
		"--target", target,
		"--full",
		"--format", "html",
	}, onLine)
}

// RunRecon runs Aegis recon: subdomain enum, DNS, OSINT, secrets, screenshots
func RunRecon(target string, onLine func(string)) error {
	dir := aegisDir()
	runAegisCommand(dir, []string{"scope", "add", target, "--kind", "domain"}, onLine)
	return runAegisCommand(dir, []string{"recon", "domain", target}, onLine)
}

// RunVulnWeb runs Aegis web vulnerability scan via Nuclei
func RunVulnWeb(target string, cookies string, onLine func(string)) error {
	dir := aegisDir()
	args := []string{"vuln", "web", target}
	if cookies != "" {
		args = append(args, "--cookies", cookies)
	}
	return runAegisCommand(dir, args, onLine)
}

// RunVulnNet runs Aegis network vulnerability scan
func RunVulnNet(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"vuln", "net", target}, onLine)
}

// RunExploitMSF runs Metasploit auto-mapping for a target
func RunExploitMSF(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"exploit", "msf", target, "--force"}, onLine)
}

// RunExploitOOB runs OOB SSRF/XXE detection via interactsh
func RunExploitOOB(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"exploit", "oob", target, "--force"}, onLine)
}

// RunSmuggling runs HTTP request smuggling detection
func RunSmuggling(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"vuln", "smuggling", target}, onLine)
}

// RunCloudRecon runs cloud asset discovery (S3, Azure, GCP)
func RunCloudRecon(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"recon", "cloud", target}, onLine)
}

// RunADEnum runs Active Directory enumeration
func RunADEnum(target, domain string, onLine func(string)) error {
	dir := aegisDir()
	args := []string{"recon", "ad", target}
	if domain != "" {
		args = append(args, "--domain", domain)
	}
	return runAegisCommand(dir, args, onLine)
}

// RunSecretScan scans for exposed secrets (trufflehog)
func RunSecretScan(target string, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"recon", "secrets", target}, onLine)
}

// RunCVECorrelate correlates findings with NVD CVEs
func RunCVECorrelate(session int, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"cve", "correlate", "--session", fmt.Sprintf("%d", session)}, onLine)
}

// RunReport generates an HTML report with D3.js attack path graph
func RunReport(target, format string, onLine func(string)) (string, error) {
	dir := aegisDir()
	if format == "" {
		format = "html"
	}
	err := runAegisCommand(dir, []string{
		"report", "generate", target,
		"--format", format,
	}, onLine)

	// Find the generated report file
	reportDir := filepath.Join(dir, "data", "reports")
	entries, _ := os.ReadDir(reportDir)
	var latest string
	var latestTime time.Time
	for _, e := range entries {
		if strings.Contains(e.Name(), target) && strings.HasSuffix(e.Name(), "."+format) {
			info, _ := e.Info()
			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				latest = filepath.Join(reportDir, e.Name())
			}
		}
	}
	return latest, err
}

// RunSARIFExport exports findings as SARIF for GitHub Code Scanning
func RunSARIFExport(session int, outputPath string, onLine func(string)) error {
	dir := aegisDir()
	args := []string{"sarif", "export", "--session", fmt.Sprintf("%d", session)}
	if outputPath != "" {
		args = append(args, "--output", outputPath)
	}
	return runAegisCommand(dir, args, onLine)
}

// RunAITriage runs AI triage on findings
func RunAITriage(session int, onLine func(string)) error {
	dir := aegisDir()
	return runAegisCommand(dir, []string{"ai", "triage", "--session", fmt.Sprintf("%d", session)}, onLine)
}

// ── Result reading from SQLite ────────────────────────────────────────────────

// GetFindings reads findings from Aegis SQLite database
func GetFindings(target string) ([]AegisFinding, error) {
	dir := aegisDir()
	dbPath := filepath.Join(dir, "data", "aegis.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, nil // no DB yet
	}

	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT id, target, title, severity, category, description, evidence, url, tool, created_at
		FROM findings
		WHERE target LIKE ?
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			created_at DESC
		LIMIT 200
	`, "%"+target+"%")
	if err != nil {
		// Table may not exist yet
		return nil, nil
	}
	defer rows.Close()

	var findings []AegisFinding
	for rows.Next() {
		var f AegisFinding
		var createdStr string
		var evidence, url, tool sql.NullString
		if err := rows.Scan(&f.ID, &f.Target, &f.Title, &f.Severity, &f.Category,
			&f.Description, &evidence, &url, &tool, &createdStr); err != nil {
			continue
		}
		f.Evidence = evidence.String
		f.URL = url.String
		f.Tool = tool.String
		f.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		findings = append(findings, f)
	}
	return findings, nil
}

// GetFindingsJSON returns findings as JSON string for AI consumption
func GetFindingsJSON(target string) string {
	findings, err := GetFindings(target)
	if err != nil || len(findings) == 0 {
		return "[]"
	}
	data, _ := json.MarshalIndent(findings, "", "  ")
	return string(data)
}

// GetFindingsSummary returns a text summary of findings
func GetFindingsSummary(target string) string {
	findings, err := GetFindings(target)
	if err != nil || len(findings) == 0 {
		return "No Aegis findings yet for " + target
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Aegis findings for %s (%d total):\n", target, len(findings)))
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := counts[sev]; n > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", strings.ToUpper(sev), n))
		}
	}
	sb.WriteString("\nTop findings:\n")
	for i, f := range findings {
		if i >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s — %s\n", strings.ToUpper(f.Severity), f.Title, f.Category))
		if f.URL != "" {
			sb.WriteString(fmt.Sprintf("    URL: %s\n", f.URL))
		}
	}
	return sb.String()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// runInVenv runs a Python command inside the venv
func runInVenv(dir string, args []string, onStatus func(AegisStatus)) error {
	return runInVenvCwd(dir, dir, args, onStatus)
}

func runInVenvCwd(dir, cwd string, args []string, onStatus func(AegisStatus)) error {
	py := venvPython()
	cmd := exec.Command(py, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(),
		"VIRTUAL_ENV="+filepath.Join(dir, ".venv"),
		"PATH="+filepath.Join(dir, ".venv", "bin")+":"+os.Getenv("PATH"),
	)

	if onStatus != nil {
		out, err := cmd.CombinedOutput()
		if onStatus != nil && len(out) > 0 {
			onStatus(AegisStatus{Step: "output", Message: string(out)})
		}
		return err
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runAegisCommand runs an aegis CLI command and streams output line by line
func runAegisCommand(dir string, args []string, onLine func(string)) error {
	aegisBin := venvAegis()

	// Ensure config dir is set
	configPath := filepath.Join(dir, "config", "config.yaml")
	fullArgs := append([]string{"--config", configPath}, args...)

	cmd := exec.Command(aegisBin, fullArgs...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"VIRTUAL_ENV="+filepath.Join(dir, ".venv"),
		"PATH="+filepath.Join(dir, ".venv", "bin")+":"+os.Getenv("PATH"),
		"AEGIS_DATA_DIR="+filepath.Join(dir, "data"),
	)
	cmd.Stdin = nil

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("aegis start failed: %w", err)
	}

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if onLine != nil {
				onLine(line)
			}
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if onLine != nil && line != "" {
				onLine("[stderr] " + line)
			}
		}
	}()

	return cmd.Wait()
}

// UpdateAPIKey updates an API key in Aegis config.yaml
func UpdateAPIKey(keyName, value string) error {
	dir := aegisDir()
	configPath := filepath.Join(dir, "config", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.Contains(line, keyName+":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				lines[i] = parts[0] + ": " + value
			}
		}
	}

	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0600)
}

// GetAegisDir returns the Aegis installation directory
func GetAegisDir() string {
	return aegisDir()
}

// GetWorkspaceDB returns the path to the active workspace SQLite DB
func GetWorkspaceDB() string {
	return filepath.Join(aegisDir(), "data", "aegis.db")
}
