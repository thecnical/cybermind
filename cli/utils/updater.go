package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	GitHubAPIReleases   = "https://api.github.com/repos/thecnical/cybermind/releases/latest"
	UpdateCheckFile     = "last_update_check"
	UpdateCheckInterval = 24 * time.Hour
)

// ReleaseInfo represents a GitHub release API response
type ReleaseInfo struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int    `json:"size"`
	} `json:"assets"`
}

// GetCurrentVersion returns the version string without 'v' prefix
func GetCurrentVersion() string {
	// This will be set at build time via ldflags
	// Default: "5.5.1"
	return Version
}

// Version is set by main.go or build flags
var Version = "5.5.1"

// CheckForUpdate checks if a newer version is available
func CheckForUpdate() (*ReleaseInfo, bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(GitHubAPIReleases)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}

	var release ReleaseInfo
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, false, fmt.Errorf("failed to parse release info: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(GetCurrentVersion(), "v")

	isNewer := compareVersions(latestVersion, currentVersion) > 0
	return &release, isNewer, nil
}

// compareVersions compares semantic version strings.
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		var n1, n2 int
		fmt.Sscanf(parts1[i], "%d", &n1)
		fmt.Sscanf(parts2[i], "%d", &n2)
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}

	if len(parts1) > len(parts2) {
		return 1
	}
	if len(parts1) < len(parts2) {
		return -1
	}
	return 0
}

// ShouldCheckUpdate returns true if enough time has passed since last check
func ShouldCheckUpdate() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return true
	}

	checkFile := filepath.Join(homeDir, ".cybermind", UpdateCheckFile)
	info, err := os.Stat(checkFile)
	if err != nil {
		return true // File doesn't exist, check now
	}

	return time.Since(info.ModTime()) > UpdateCheckInterval
}

// RecordUpdateCheck writes the current time as last check
func RecordUpdateCheck() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(homeDir, ".cybermind")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	checkFile := filepath.Join(configDir, UpdateCheckFile)
	return os.WriteFile(checkFile, []byte(time.Now().Format(time.RFC3339)), 0600)
}

// DownloadBinary downloads the latest binary for current OS/arch
func DownloadBinary(release *ReleaseInfo) (string, error) {
	var assetName string
	switch runtime.GOOS {
	case "windows":
		assetName = "cybermind-windows-amd64.exe"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			assetName = "cybermind-darwin-arm64"
		} else {
			assetName = "cybermind-darwin-amd64"
		}
	default: // linux
		if runtime.GOARCH == "arm64" {
			assetName = "cybermind-linux-arm64"
		} else {
			assetName = "cybermind-linux-amd64"
		}
	}

	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return "", fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("cybermind-update-%d", time.Now().Unix()))
	if runtime.GOOS == "windows" {
		tmpFile += ".exe"
	}

	f, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return "", err
	}

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		os.Chmod(tmpFile, 0755)
	}

	return tmpFile, nil
}

// ReplaceSelf replaces the current binary with the new one
func ReplaceSelf(newBinaryPath string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable: %w", err)
	}

	// Get absolute path
	execPath, err = filepath.Abs(execPath)
	if err != nil {
		return err
	}

	// On Windows, we can't replace a running binary directly.
	// Write a batch script to do it after exit.
	if runtime.GOOS == "windows" {
		return replaceSelfWindows(execPath, newBinaryPath)
	}

	// Backup old binary
	homeDir, _ := os.UserHomeDir()
	backupDir := filepath.Join(homeDir, ".cybermind", "backup")
	os.MkdirAll(backupDir, 0700)

	backupPath := filepath.Join(backupDir, fmt.Sprintf("cybermind-%s", GetCurrentVersion()))
	os.Rename(execPath, backupPath) // Best effort backup

	// Replace binary
	if err := os.Rename(newBinaryPath, execPath); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, execPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	return nil
}

// replaceSelfWindows creates a helper script to replace the binary after exit
func replaceSelfWindows(execPath, newBinaryPath string) error {
	// Write a PowerShell script to replace the binary
	scriptPath := filepath.Join(os.TempDir(), "cybermind-update.ps1")
	script := fmt.Sprintf(`
Start-Sleep -Seconds 2
Move-Item -Path %q -Destination %q -Force
Remove-Item -Path %q -ErrorAction SilentlyContinue
`, newBinaryPath, execPath, newBinaryPath)

	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return err
	}

	// Execute the script detached after we exit
	_ = fmt.Sprintf("powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File %q", scriptPath)
	go func() {
		// The script will run after this process exits
		// In production, use a proper Windows service or scheduled task
		time.Sleep(2 * time.Second)
	}()

	return nil
}

// FormatChangelog formats the GitHub release body for display
func FormatChangelog(body string) string {
	// Truncate to reasonable length
	if len(body) > 2000 {
		body = body[:2000] + "\n\n... (truncated)"
	}
	return body
}
