// mobile.go — Mobile App Security Testing Engine
// APK decompilation, static analysis, SSL pinning bypass, Frida hooking,
// hardcoded secret detection, and API endpoint extraction.
package brain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// MobileFinding represents a finding from mobile app analysis
type MobileFinding struct {
	Type        string
	Severity    string
	File        string
	Value       string
	Description string
	PoC         string
}

// MobileScanResult holds all mobile app findings
type MobileScanResult struct {
	APKPath     string
	PackageName string
	Findings    []MobileFinding
	Endpoints   []string
	Secrets     []string
	Duration    time.Duration
	Error       string
}

var mobileSecretPatterns = []struct {
	name     string
	pattern  *regexp.Regexp
	severity string
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "critical"},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "high"},
	{"Firebase URL", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), "high"},
	{"Stripe Secret", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), "critical"},
	{"GitHub Token", regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), "critical"},
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "high"},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`), "critical"},
	{"Hardcoded Password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']`), "high"},
	{"Hardcoded API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*["']([a-zA-Z0-9_\-]{16,})["']`), "high"},
}

var mobileEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9/_\-{}?=&]+`),
	regexp.MustCompile(`["'](/api/[a-zA-Z0-9/_\-{}]+)["']`),
	regexp.MustCompile(`["'](/v[0-9]+/[a-zA-Z0-9/_\-{}]+)["']`),
}

// AnalyzeAPK performs full static analysis of an Android APK
func AnalyzeAPK(apkPath string) MobileScanResult {
	start := time.Now()
	result := MobileScanResult{APKPath: apkPath}

	decompileDir := "/tmp/cybermind_apk_" + filepath.Base(apkPath)
	if err := decompileAPK(apkPath, decompileDir); err != nil {
		result.Error = "Decompile failed: " + err.Error()
		return result
	}
	defer os.RemoveAll(decompileDir)

	jadxDir := "/tmp/cybermind_jadx_" + filepath.Base(apkPath)
	jadxAvailable := decompileWithJADX(apkPath, jadxDir) == nil
	if jadxAvailable {
		defer os.RemoveAll(jadxDir)
	}

	result.PackageName = extractPackageName(decompileDir)

	scanDir := decompileDir
	if jadxAvailable {
		scanDir = jadxDir
	}

	result.Findings = append(result.Findings, scanForSecrets(scanDir)...)
	result.Endpoints = extractMobileEndpoints(scanDir)

	if hasSSlPinning(scanDir) {
		result.Findings = append(result.Findings, MobileFinding{
			Type:        "ssl_pinning_detected",
			Severity:    "info",
			Description: "SSL certificate pinning detected — use Frida to bypass",
			PoC:         generateFridaSSLBypassScript(result.PackageName),
		})
	}

	result.Findings = append(result.Findings, checkWeakCrypto(scanDir)...)
	result.Findings = append(result.Findings, checkExportedComponents(decompileDir)...)

	for _, f := range result.Findings {
		if f.Type == "hardcoded_secret" && f.Value != "" {
			result.Secrets = append(result.Secrets, f.Value)
		}
	}

	result.Duration = time.Since(start)
	return result
}

func decompileAPK(apkPath, outputDir string) error {
	if _, err := exec.LookPath("apktool"); err != nil {
		cmd := exec.Command("sudo", "apt-get", "install", "-y", "-qq", "apktool")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		cmd.Stdin = nil
		if err2 := cmd.Run(); err2 != nil {
			return fmt.Errorf("apktool not found")
		}
	}
	os.RemoveAll(outputDir)
	cmd := exec.Command("apktool", "d", apkPath, "-o", outputDir, "-f", "--no-src")
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 120)
	if err != nil {
		return fmt.Errorf("apktool failed: %v\n%s", err, out)
	}
	return nil
}

func decompileWithJADX(apkPath, outputDir string) error {
	if _, err := exec.LookPath("jadx"); err != nil {
		return fmt.Errorf("jadx not found")
	}
	os.RemoveAll(outputDir)
	cmd := exec.Command("jadx", "-d", outputDir, "--no-res", apkPath)
	cmd.Stdin = nil
	_, err := runWithTimeout(cmd, 180)
	return err
}

func extractPackageName(decompileDir string) string {
	data, err := os.ReadFile(decompileDir + "/AndroidManifest.xml")
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`package="([^"]+)"`)
	m := re.FindSubmatch(data)
	if len(m) > 1 {
		return string(m[1])
	}
	return ""
}

func scanForSecrets(dir string) []MobileFinding {
	var findings []MobileFinding
	seen := make(map[string]bool)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".xml" && ext != ".json" &&
			ext != ".smali" && ext != ".js" && ext != ".properties" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		for _, pattern := range mobileSecretPatterns {
			matches := pattern.pattern.FindAllString(content, -1)
			for _, match := range matches {
				if isObviousFalsePositive(match) {
					continue
				}
				key := pattern.name + "|" + match[:min(20, len(match))]
				if !seen[key] {
					seen[key] = true
					findings = append(findings, MobileFinding{
						Type:        "hardcoded_secret",
						Severity:    pattern.severity,
						File:        strings.TrimPrefix(path, dir+"/"),
						Value:       truncateSecret(match),
						Description: fmt.Sprintf("%s found in %s", pattern.name, filepath.Base(path)),
					})
				}
			}
		}
		return nil
	})
	return findings
}

func extractMobileEndpoints(dir string) []string {
	var endpoints []string
	seen := make(map[string]bool)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".js" && ext != ".xml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		for _, pattern := range mobileEndpointPatterns {
			for _, match := range pattern.FindAllString(content, -1) {
				if !seen[match] && len(match) > 10 && len(match) < 200 &&
					!strings.Contains(match, "example.com") &&
					!strings.Contains(match, "schema.org") {
					seen[match] = true
					endpoints = append(endpoints, match)
				}
			}
		}
		return nil
	})
	return endpoints
}

func hasSSlPinning(dir string) bool {
	indicators := []string{"CertificatePinner", "TrustManager", "X509TrustManager",
		"checkServerTrusted", "TrustKit", "ssl_pinning", "OkHttpClient"}
	found := false
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if found || err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".smali" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		for _, indicator := range indicators {
			if strings.Contains(content, indicator) {
				found = true
				return nil
			}
		}
		return nil
	})
	return found
}

func checkWeakCrypto(dir string) []MobileFinding {
	var findings []MobileFinding
	weakCrypto := map[string]string{
		"MD5":      "MD5 is cryptographically broken — use SHA-256",
		"SHA1":     "SHA-1 is deprecated — use SHA-256",
		"DES":      "DES is insecure — use AES-256",
		"RC4":      "RC4 is broken — use AES-256",
		"Random()": "java.util.Random is not cryptographically secure — use SecureRandom",
	}
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		for crypto, desc := range weakCrypto {
			if strings.Contains(content, crypto) {
				findings = append(findings, MobileFinding{
					Type: "weak_crypto", Severity: "medium",
					File: filepath.Base(path), Description: desc,
				})
				break
			}
		}
		return nil
	})
	return findings
}

func checkExportedComponents(decompileDir string) []MobileFinding {
	var findings []MobileFinding
	data, err := os.ReadFile(decompileDir + "/AndroidManifest.xml")
	if err != nil {
		return nil
	}
	content := string(data)
	activityRe := regexp.MustCompile(`<activity[^>]+android:name="([^"]+)"[^>]+android:exported="true"`)
	for _, m := range activityRe.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			findings = append(findings, MobileFinding{
				Type: "exported_component", Severity: "medium",
				Description: fmt.Sprintf("Exported Activity: %s — accessible by other apps", m[1]),
				PoC:         fmt.Sprintf("adb shell am start -n <package>/%s", m[1]),
			})
		}
	}
	return findings
}

func generateFridaSSLBypassScript(packageName string) string {
	return fmt.Sprintf(`# Frida SSL Pinning Bypass for %s
# Step 1: pip3 install frida-tools
# Step 2: Push frida-server to device:
#   adb push frida-server /data/local/tmp/
#   adb shell chmod 755 /data/local/tmp/frida-server
#   adb shell /data/local/tmp/frida-server &
# Step 3: Run bypass:
#   frida -U -f %s --no-pause -l ssl_bypass.js
# Step 4: Route traffic through ZAP (port 8090)`, packageName, packageName)
}

// FormatMobileReport returns a human-readable mobile scan report
func FormatMobileReport(result MobileScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  📱 Mobile App Analysis — %s\n", filepath.Base(result.APKPath)))
	if result.PackageName != "" {
		sb.WriteString(fmt.Sprintf("  Package: %s\n", result.PackageName))
	}
	sb.WriteString(fmt.Sprintf("  Duration: %s | Findings: %d | Endpoints: %d | Secrets: %d\n\n",
		result.Duration.Round(time.Second), len(result.Findings), len(result.Endpoints), len(result.Secrets)))
	if result.Error != "" {
		sb.WriteString("  Error: " + result.Error + "\n")
		return sb.String()
	}
	for i, f := range result.Findings {
		sb.WriteString(fmt.Sprintf("  [%d] [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Type))
		sb.WriteString(fmt.Sprintf("      %s\n", f.Description))
		if f.File != "" {
			sb.WriteString(fmt.Sprintf("      File: %s\n", f.File))
		}
		sb.WriteString("\n")
	}
	if len(result.Endpoints) > 0 {
		sb.WriteString(fmt.Sprintf("  API Endpoints (%d):\n", len(result.Endpoints)))
		for _, ep := range result.Endpoints[:min(20, len(result.Endpoints))] {
			sb.WriteString(fmt.Sprintf("    %s\n", ep))
		}
	}
	return sb.String()
}
