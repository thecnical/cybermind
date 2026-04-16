// zap.go — OWASP ZAP Integration (Free Burp Suite Alternative)
// Full headless ZAP scanning: active scan, passive scan, spider, fuzzer, AJAX spider.
package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	zapAPIKey  = "cybermind2024"
	zapPort    = "8090"
	zapBaseURL = "http://localhost:8090"
)

// ZAPScanResult holds results from a ZAP scan
type ZAPScanResult struct {
	Target     string
	Alerts     []ZAPAlert
	ScanID     string
	Duration   time.Duration
	SpiderURLs int
	Error      string
}

// ZAPAlert represents a single ZAP finding
type ZAPAlert struct {
	Alert       string `json:"alert"`
	Risk        string `json:"risk"`
	Confidence  string `json:"confidence"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Solution    string `json:"solution"`
	Evidence    string `json:"evidence"`
	CWEId       string `json:"cweid"`
	WASCID      string `json:"wascid"`
}

var zapHTTPClient = &http.Client{Timeout: 30 * time.Second}

// IsZAPRunning checks if ZAP daemon is running
func IsZAPRunning() bool {
	resp, err := zapHTTPClient.Get(zapBaseURL + "/JSON/core/view/version/?apikey=" + zapAPIKey)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// StartZAPDaemon starts ZAP in headless daemon mode
func StartZAPDaemon() error {
	if IsZAPRunning() {
		return nil
	}
	zapPaths := []string{
		"/usr/share/zaproxy/zap.sh",
		"/opt/zaproxy/zap.sh",
		"/usr/bin/zaproxy",
		"zaproxy",
	}
	zapBin := ""
	for _, p := range zapPaths {
		if _, err := os.Stat(p); err == nil {
			zapBin = p
			break
		}
		if _, err := exec.LookPath(p); err == nil {
			zapBin = p
			break
		}
	}
	if zapBin == "" {
		if err := installZAP(); err != nil {
			return fmt.Errorf("ZAP not found and install failed: %v", err)
		}
		zapBin = "zaproxy"
	}
	cmd := exec.Command(zapBin,
		"-daemon", "-port", zapPort,
		"-config", "api.key="+zapAPIKey,
		"-config", "api.addrs.addr.name=.*",
		"-config", "api.addrs.addr.regex=true",
		"-nostdout",
	)
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ZAP: %v", err)
	}
	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		if IsZAPRunning() {
			return nil
		}
	}
	return fmt.Errorf("ZAP started but not responding after 60s")
}

func installZAP() error {
	cmd := exec.Command("sudo", "apt-get", "install", "-y", "-qq", "zaproxy")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdin = nil
	if err := cmd.Run(); err == nil {
		return nil
	}
	cmd2 := exec.Command("sudo", "snap", "install", "zaproxy", "--classic")
	cmd2.Stdin = nil
	return cmd2.Run()
}

func zapAPI(endpoint string, params map[string]string) (map[string]interface{}, error) {
	u := zapBaseURL + endpoint + "?apikey=" + zapAPIKey
	for k, v := range params {
		u += "&" + k + "=" + url.QueryEscape(v)
	}
	resp, err := zapHTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("ZAP API error: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ZAP response parse error: %v", err)
	}
	return result, nil
}

// RunZAPScan performs a full ZAP scan: spider + active scan + get alerts
func RunZAPScan(target string, scanType string, onProgress func(string)) ZAPScanResult {
	start := time.Now()
	result := ZAPScanResult{Target: target}

	if !IsZAPRunning() {
		onProgress("Starting ZAP daemon...")
		if err := StartZAPDaemon(); err != nil {
			result.Error = "ZAP not available: " + err.Error()
			return result
		}
	}
	onProgress("ZAP daemon ready")

	contextName := "cybermind_" + strings.ReplaceAll(target, ".", "_")
	zapAPI("/JSON/context/action/newContext/", map[string]string{"contextName": contextName})
	zapAPI("/JSON/context/action/includeInContext/", map[string]string{
		"contextName": contextName,
		"regex":       ".*" + strings.ReplaceAll(target, ".", "\\.") + ".*",
	})

	// Spider
	onProgress("Spidering target: " + target)
	spiderResp, err := zapAPI("/JSON/spider/action/scan/", map[string]string{
		"url": target, "contextName": contextName, "recurse": "true", "maxChildren": "50",
	})
	if err != nil {
		result.Error = "Spider failed: " + err.Error()
		return result
	}
	spiderID := "0"
	if spiderResp != nil {
		if id, ok := spiderResp["scan"].(string); ok {
			spiderID = id
		}
	}
	for i := 0; i < 120; i++ {
		time.Sleep(2 * time.Second)
		statusResp, err := zapAPI("/JSON/spider/view/status/", map[string]string{"scanId": spiderID})
		if err != nil {
			break
		}
		if status, ok := statusResp["status"].(string); ok {
			onProgress(fmt.Sprintf("Spider: %s%%", status))
			if status == "100" {
				break
			}
		}
	}

	// AJAX Spider for JS-heavy apps
	if scanType == "full" || scanType == "ajax" {
		onProgress("Running AJAX spider...")
		zapAPI("/JSON/ajaxSpider/action/scan/", map[string]string{"url": target, "contextName": contextName})
		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			statusResp, _ := zapAPI("/JSON/ajaxSpider/view/status/", nil)
			if statusResp != nil {
				if status, ok := statusResp["status"].(string); ok && status == "stopped" {
					break
				}
			}
		}
		zapAPI("/JSON/ajaxSpider/action/stop/", nil)
	}

	// Passive scan
	onProgress("Passive scan running...")
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		passiveResp, _ := zapAPI("/JSON/pscan/view/recordsToScan/", nil)
		if passiveResp != nil {
			if records, ok := passiveResp["recordsToScan"].(string); ok && records == "0" {
				break
			}
		}
	}

	// Active scan
	if scanType == "full" || scanType == "active" {
		onProgress("Starting active scan (5-30 min)...")
		activeScanResp, err := zapAPI("/JSON/ascan/action/scan/", map[string]string{
			"url": target, "recurse": "true",
		})
		if err == nil && activeScanResp != nil {
			if scanID, ok := activeScanResp["scan"].(string); ok {
				result.ScanID = scanID
				for i := 0; i < 300; i++ {
					time.Sleep(2 * time.Second)
					statusResp, _ := zapAPI("/JSON/ascan/view/status/", map[string]string{"scanId": scanID})
					if statusResp != nil {
						if status, ok := statusResp["status"].(string); ok {
							onProgress(fmt.Sprintf("Active scan: %s%%", status))
							if status == "100" {
								break
							}
						}
					}
				}
			}
		}
	}

	// Get alerts
	onProgress("Collecting findings...")
	alertsResp, err := zapAPI("/JSON/alert/view/alerts/", map[string]string{
		"baseurl": target, "start": "0", "count": "1000",
	})
	if err != nil {
		result.Error = "Failed to get alerts: " + err.Error()
		return result
	}
	if alertsResp != nil {
		if alertsRaw, ok := alertsResp["alerts"].([]interface{}); ok {
			for _, alertRaw := range alertsRaw {
				if alertMap, ok := alertRaw.(map[string]interface{}); ok {
					alert := ZAPAlert{
						Alert:       zapGetString(alertMap, "alert"),
						Risk:        zapGetString(alertMap, "risk"),
						Confidence:  zapGetString(alertMap, "confidence"),
						URL:         zapGetString(alertMap, "url"),
						Description: zapGetString(alertMap, "description"),
						Solution:    zapGetString(alertMap, "solution"),
						Evidence:    zapGetString(alertMap, "evidence"),
						CWEId:       zapGetString(alertMap, "cweid"),
					}
					if alert.Risk == "High" || alert.Risk == "Medium" || alert.Risk == "Critical" {
						result.Alerts = append(result.Alerts, alert)
					}
				}
			}
		}
	}
	result.Duration = time.Since(start)
	onProgress(fmt.Sprintf("ZAP complete: %d findings in %s", len(result.Alerts), result.Duration.Round(time.Second)))
	return result
}

// FormatZAPReport returns a human-readable ZAP scan report
func FormatZAPReport(result ZAPScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  🔍 ZAP Scan Report — %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("  Duration: %s | Findings: %d\n\n",
		result.Duration.Round(time.Second), len(result.Alerts)))
	if result.Error != "" {
		sb.WriteString("  Error: " + result.Error + "\n")
		return sb.String()
	}
	if len(result.Alerts) == 0 {
		sb.WriteString("  No medium/high risk findings.\n")
		return sb.String()
	}
	for _, a := range result.Alerts {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n    URL: %s\n", a.Risk, a.Alert, a.URL))
		if a.Evidence != "" {
			ev := a.Evidence
			if len(ev) > 100 {
				ev = ev[:100] + "..."
			}
			sb.WriteString(fmt.Sprintf("    Evidence: %s\n", ev))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// StopZAP shuts down the ZAP daemon
func StopZAP() {
	zapAPI("/JSON/core/action/shutdown/", nil)
}

func zapGetString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
