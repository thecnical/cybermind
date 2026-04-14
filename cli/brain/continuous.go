// continuous.go — Continuous Loop Mode + Execution Modes
// /plan --continuous: runs overnight, picks targets, hunts bugs, submits reports.
// Execution modes: quick (30min), deep (4h), overnight (12h).
package brain

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ExecutionMode controls how deep the scan goes.
type ExecutionMode string

const (
	ModeQuick     ExecutionMode = "quick"     // ~30 min: fast tools only
	ModeDeep      ExecutionMode = "deep"      // ~4 hours: all tools, full flags
	ModeOvernight ExecutionMode = "overnight" // ~12 hours: reconftw -a, everything
)

// ExecutionConfig holds settings for a scan run.
type ExecutionConfig struct {
	Mode            ExecutionMode
	Target          string
	Platform        string // hackerone, bugcrowd
	ProgramHandle   string
	AutoSubmit      bool
	FocusTypes      []string // xss, idor, ssrf, sqli, rce
	SkillLevel      string   // beginner, intermediate, advanced
	MaxTargets      int      // for continuous mode
	ContinuousLoop  bool
}

// ModeSettings holds tool-specific settings for each execution mode.
type ModeSettings struct {
	ReconftWFlags    []string
	NucleiThreads    int
	SubfinderThreads int
	FFUFThreads      int
	NmapFlags        []string
	MaxToolTimeout   int // seconds per tool
	RunReconftw      bool
	RunFullNuclei    bool
	RunBurp          bool
}

// GetModeSettings returns tool settings for the given execution mode.
func GetModeSettings(mode ExecutionMode) ModeSettings {
	switch mode {
	case ModeQuick:
		return ModeSettings{
			ReconftWFlags:    []string{"-s"},                    // passive only
			NucleiThreads:    100,
			SubfinderThreads: 100,
			FFUFThreads:      100,
			NmapFlags:        []string{"-T4", "--top-ports", "1000"},
			MaxToolTimeout:   300,  // 5 min per tool
			RunReconftw:      false, // too slow for quick mode
			RunFullNuclei:    false,
			RunBurp:          false,
		}
	case ModeDeep:
		return ModeSettings{
			ReconftWFlags:    []string{"-r", "--parallel"},      // full recon
			NucleiThreads:    300,
			SubfinderThreads: 300,
			FFUFThreads:      200,
			NmapFlags:        []string{"-sV", "-sC", "-T4", "-p-", "--min-rate", "5000"},
			MaxToolTimeout:   3600, // 1 hour per tool
			RunReconftw:      true,
			RunFullNuclei:    true,
			RunBurp:          false,
		}
	case ModeOvernight:
		return ModeSettings{
			ReconftWFlags:    []string{"-a", "--deep", "--parallel"}, // ALL modules
			NucleiThreads:    500,
			SubfinderThreads: 500,
			FFUFThreads:      300,
			NmapFlags:        []string{"-sS", "-sV", "-sC", "-T4", "-p-", "--min-rate", "10000", "--script", "vuln,auth,http-vuln*"},
			MaxToolTimeout:   21600, // 6 hours per tool
			RunReconftw:      true,
			RunFullNuclei:    true,
			RunBurp:          true,
		}
	default:
		return GetModeSettings(ModeDeep)
	}
}

// SetModeEnv sets environment variables that tools read to adjust their behavior.
func SetModeEnv(mode ExecutionMode) {
	settings := GetModeSettings(mode)
	os.Setenv("CYBERMIND_MODE", string(mode))
	os.Setenv("CYBERMIND_NUCLEI_THREADS", fmt.Sprintf("%d", settings.NucleiThreads))
	os.Setenv("CYBERMIND_SUBFINDER_THREADS", fmt.Sprintf("%d", settings.SubfinderThreads))
	os.Setenv("CYBERMIND_FFUF_THREADS", fmt.Sprintf("%d", settings.FFUFThreads))
	os.Setenv("CYBERMIND_MAX_TOOL_TIMEOUT", fmt.Sprintf("%d", settings.MaxToolTimeout))
	if settings.RunReconftw {
		os.Setenv("CYBERMIND_RUN_RECONFTW", "true")
		os.Setenv("CYBERMIND_RECONFTW_FLAGS", strings.Join(settings.ReconftWFlags, " "))
	}
	if settings.RunFullNuclei {
		os.Setenv("CYBERMIND_FULL_NUCLEI", "true")
	}
}

// ContinuousSession manages a continuous bug hunting session.
type ContinuousSession struct {
	Config      ExecutionConfig
	StartTime   time.Time
	TargetsDone []string
	BugsFound   []Bug
	TotalRuns   int
	Running     bool
	LogFile     string
}

// NewContinuousSession creates a new continuous hunting session.
func NewContinuousSession(cfg ExecutionConfig) *ContinuousSession {
	logFile := fmt.Sprintf("/tmp/cybermind_continuous_%s.log",
		time.Now().Format("2006-01-02_15-04-05"))
	return &ContinuousSession{
		Config:    cfg,
		StartTime: time.Now(),
		LogFile:   logFile,
	}
}

// Log writes a message to the session log.
func (s *ContinuousSession) Log(msg string) {
	f, err := os.OpenFile(s.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("15:04:05")
	fmt.Fprintf(f, "[%s] %s\n", timestamp, msg)
}

// GetNextTarget picks the next best target to test.
// Uses memory to avoid retesting recent targets and picks high-value ones.
func GetNextTarget(cfg ExecutionConfig, alreadyTested []string) string {
	// If specific target given, use it
	if cfg.Target != "" && !containsStr(alreadyTested, cfg.Target) {
		return cfg.Target
	}

	// Load global memory to find untested high-value targets
	g := LoadGlobal()
	_ = g // use for future prioritization

	// Default curated list of good bug bounty targets
	// These are programs known for good scope and fair bounties
	defaultTargets := []string{
		"hackerone.com",
		"bugcrowd.com",
		"gitlab.com",
		"nextcloud.com",
		"wordpress.org",
		"drupal.org",
		"joomla.org",
		"mattermost.com",
		"rocket.chat",
		"discourse.org",
	}

	for _, t := range defaultTargets {
		if !containsStr(alreadyTested, t) {
			return t
		}
	}

	return "" // all tested
}

// ShouldContinue returns true if the continuous session should keep running.
func (s *ContinuousSession) ShouldContinue() bool {
	if !s.Running {
		return false
	}
	// Stop after 12 hours in overnight mode
	if s.Config.Mode == ModeOvernight && time.Since(s.StartTime) > 12*time.Hour {
		return false
	}
	// Stop after max targets
	if s.Config.MaxTargets > 0 && len(s.TargetsDone) >= s.Config.MaxTargets {
		return false
	}
	return true
}

// PrintSessionSummary prints a summary of the continuous session.
func (s *ContinuousSession) PrintSessionSummary() string {
	duration := time.Since(s.StartTime).Round(time.Minute)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  ⚡ CONTINUOUS SESSION SUMMARY\n"))
	sb.WriteString(fmt.Sprintf("  Duration:      %s\n", duration))
	sb.WriteString(fmt.Sprintf("  Targets tested: %d\n", len(s.TargetsDone)))
	sb.WriteString(fmt.Sprintf("  Total bugs:    %d\n", len(s.BugsFound)))
	sb.WriteString(fmt.Sprintf("  Runs:          %d\n", s.TotalRuns))

	if len(s.BugsFound) > 0 {
		sb.WriteString("\n  Bugs found:\n")
		for _, b := range s.BugsFound {
			sb.WriteString(fmt.Sprintf("  [%s] %s — %s\n",
				strings.ToUpper(b.Severity), b.Title, b.URL))
		}
	}
	return sb.String()
}

// ─── Burp Suite Integration ───────────────────────────────────────────────────

// BurpConfig holds Burp Suite configuration.
type BurpConfig struct {
	JarPath    string // path to burpsuite_pro.jar
	APIPort    int    // Burp REST API port (default 1337)
	ProjectDir string // where to save project files
}

// DefaultBurpConfig returns default Burp configuration.
func DefaultBurpConfig() BurpConfig {
	home, _ := os.UserHomeDir()
	return BurpConfig{
		JarPath:    findBurpJar(),
		APIPort:    1337,
		ProjectDir: home + "/.cybermind/burp_projects",
	}
}

// findBurpJar searches common locations for Burp Suite jar.
func findBurpJar() string {
	locations := []string{
		"/opt/BurpSuitePro/BurpSuitePro.jar",
		"/opt/burpsuite/burpsuite_pro.jar",
		os.Getenv("HOME") + "/BurpSuitePro/BurpSuitePro.jar",
		"/usr/share/burpsuite/burpsuite.jar",
		"/opt/BurpSuiteCommunity/BurpSuiteCommunity.jar",
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}
	return ""
}

// IsBurpAvailable returns true if Burp Suite is installed and accessible.
func IsBurpAvailable() bool {
	cfg := DefaultBurpConfig()
	if cfg.JarPath != "" {
		return true
	}
	// Check if burpsuite command exists
	_, err := exec.LookPath("burpsuite")
	return err == nil
}

// LaunchBurpScan starts a Burp Suite headless scan against a target.
// Returns the project file path where results are saved.
func LaunchBurpScan(target string, cfg BurpConfig) (string, error) {
	if cfg.JarPath == "" {
		return "", fmt.Errorf("Burp Suite not found — install at /opt/BurpSuitePro/")
	}

	if err := os.MkdirAll(cfg.ProjectDir, 0700); err != nil {
		return "", err
	}

	safeTarget := strings.ReplaceAll(strings.ReplaceAll(target, ".", "_"), "/", "_")
	projectFile := fmt.Sprintf("%s/cybermind_%s_%s.burp",
		cfg.ProjectDir, safeTarget, time.Now().Format("2006-01-02"))

	// Create Burp scan config
	scanConfig := buildBurpScanConfig(target)
	configFile := "/tmp/cybermind_burp_config.json"
	if err := os.WriteFile(configFile, []byte(scanConfig), 0644); err != nil {
		return "", err
	}

	// Launch Burp headless
	cmd := exec.Command("java", "-jar", cfg.JarPath,
		"--project-file="+projectFile,
		"--config-file="+configFile,
		"--unpause-spider-and-scanner",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start Burp: %v", err)
	}

	return projectFile, nil
}

// buildBurpScanConfig generates a Burp scan configuration JSON.
func buildBurpScanConfig(target string) string {
	return fmt.Sprintf(`{
  "target": {
    "scope": {
      "advanced_mode": true,
      "include": [{"enabled": true, "scheme": "https", "host": "%s", "port": "443", "file": ".*"}]
    }
  },
  "scanner": {
    "active_scanning_optimization": "thorough",
    "active_scanning_areas": {
      "scan_everything": true
    }
  },
  "spider": {
    "max_link_depth": 10,
    "max_parameterized_requests_per_url": 100
  }
}`, target)
}

// containsStr checks if a string slice contains a value.
func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
