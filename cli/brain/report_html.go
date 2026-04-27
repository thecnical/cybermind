// brain/report_html.go — HTML report generation for CyberMind scan results
// Generates a self-contained HTML report with:
// - Executive summary
// - Vulnerability findings with severity
// - Subdomain timeline
// - Tech stack visualization
// - WAF detection
// - JS secrets
// - Cloud buckets
// - Takeover candidates
// - Hotlist
package brain

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportData holds all data needed to generate an HTML report.
type ReportData struct {
	Target       string
	ScanMode     string
	StartTime    time.Time
	EndTime      time.Time
	RunID        string

	// Assets
	Subdomains   []string
	LiveURLs     []string
	OpenPorts    []int
	Technologies []string
	WAFDetected  bool
	WAFVendor    string

	// Vulnerabilities
	Vulns        []SnapshotVuln
	JSSecrets    []string
	CloudBuckets []string
	Takeovers    []string
	Emails       []string

	// JS Analysis
	JSEndpoints  []string
	VulnLibs     []string
	CMSDetected  string

	// Diff (if incremental)
	Diff         *ScanDiff

	// Hotlist
	Hotlist      []HotlistEntry

	// Tool outputs summary
	ToolsRun     []string
	ToolsFailed  []string
}

// GenerateHTMLReport generates a self-contained HTML report and saves it.
// Returns the path to the generated report.
func GenerateHTMLReport(data ReportData) (string, error) {
	home, _ := os.UserHomeDir()
	reportDir := filepath.Join(home, ".cybermind", "reports",
		strings.ReplaceAll(data.Target, ".", "_"))
	os.MkdirAll(reportDir, 0755)

	reportFile := filepath.Join(reportDir,
		fmt.Sprintf("report_%s.html", data.RunID))

	html := buildHTMLReport(data)
	if err := os.WriteFile(reportFile, []byte(html), 0644); err != nil {
		return "", err
	}
	return reportFile, nil
}

// buildHTMLReport constructs the full HTML report string.
func buildHTMLReport(data ReportData) string {
	elapsed := data.EndTime.Sub(data.StartTime).Round(time.Second)

	// Count by severity
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	for _, v := range data.Vulns {
		switch v.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberMind Report — ` + html.EscapeString(data.Target) + `</title>
<style>
:root {
  --bg: #0a0a0f;
  --bg2: #111118;
  --bg3: #1a1a24;
  --border: rgba(255,255,255,0.08);
  --text: #e0e0e0;
  --dim: #8b949e;
  --cyan: #00d4ff;
  --green: #00ff88;
  --red: #ff4444;
  --orange: #ff6600;
  --yellow: #ffd700;
  --purple: #7c3aed;
  --critical: #ff2222;
  --high: #ff6600;
  --medium: #ffd700;
  --low: #00d4ff;
  --info: #8b949e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
.header { text-align: center; margin-bottom: 48px; padding: 40px; background: var(--bg2); border: 1px solid var(--border); border-radius: 16px; }
.logo { font-size: 28px; font-weight: 800; background: linear-gradient(135deg, #00d4ff, #7c3aed); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
.target { font-size: 22px; color: var(--cyan); font-weight: 600; margin-bottom: 16px; }
.meta { color: var(--dim); font-size: 13px; }
.section { margin-bottom: 32px; }
.section-title { font-size: 18px; font-weight: 700; color: var(--cyan); margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; }
.grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
.stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
.stat-num { font-size: 36px; font-weight: 800; }
.stat-label { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }
.badge-critical { background: rgba(255,34,34,0.15); color: var(--critical); border: 1px solid rgba(255,34,34,0.3); }
.badge-high { background: rgba(255,102,0,0.15); color: var(--high); border: 1px solid rgba(255,102,0,0.3); }
.badge-medium { background: rgba(255,215,0,0.15); color: var(--medium); border: 1px solid rgba(255,215,0,0.3); }
.badge-low { background: rgba(0,212,255,0.15); color: var(--low); border: 1px solid rgba(0,212,255,0.3); }
.badge-info { background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid rgba(139,148,158,0.3); }
.badge-new { background: rgba(0,255,136,0.15); color: var(--green); border: 1px solid rgba(0,255,136,0.3); }
table { width: 100%; border-collapse: collapse; }
th { padding: 10px 16px; text-align: left; color: var(--dim); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; border-bottom: 1px solid var(--border); }
td { padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 13px; }
tr:hover td { background: rgba(255,255,255,0.02); }
.url { color: var(--cyan); font-family: monospace; font-size: 12px; word-break: break-all; }
.evidence { color: var(--dim); font-family: monospace; font-size: 11px; word-break: break-all; }
.tag { display: inline-block; background: rgba(124,58,237,0.15); border: 1px solid rgba(124,58,237,0.3); color: #a78bfa; padding: 2px 8px; border-radius: 8px; font-size: 11px; margin: 2px; }
.hotlist-item { display: flex; align-items: flex-start; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
.hotlist-score { font-size: 20px; font-weight: 800; min-width: 48px; text-align: center; }
.score-high { color: var(--critical); }
.score-med { color: var(--high); }
.score-low { color: var(--medium); }
.list-item { padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-family: monospace; font-size: 12px; color: var(--text); }
.list-item:last-child { border-bottom: none; }
.waf-badge { display: inline-flex; align-items: center; gap: 6px; background: rgba(255,102,0,0.1); border: 1px solid rgba(255,102,0,0.3); color: var(--orange); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
.no-waf { display: inline-flex; align-items: center; gap: 6px; background: rgba(0,255,136,0.1); border: 1px solid rgba(0,255,136,0.3); color: var(--green); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
.diff-new { color: var(--green); }
.diff-removed { color: var(--red); }
.footer { text-align: center; color: var(--dim); font-size: 12px; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); }
.progress-bar { height: 6px; background: var(--bg3); border-radius: 3px; overflow: hidden; margin-top: 8px; }
.progress-fill { height: 100%; border-radius: 3px; }
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
  <div class="logo">⚡ CyberMind</div>
  <div class="target">` + html.EscapeString(data.Target) + `</div>
  <div class="meta">
    Mode: <strong>` + html.EscapeString(data.ScanMode) + `</strong> &nbsp;|&nbsp;
    Started: <strong>` + data.StartTime.Format("2006-01-02 15:04:05") + `</strong> &nbsp;|&nbsp;
    Duration: <strong>` + elapsed.String() + `</strong> &nbsp;|&nbsp;
    Run ID: <strong>` + html.EscapeString(data.RunID) + `</strong>
  </div>
</div>

<!-- Summary Stats -->
<div class="grid-4">
  <div class="stat-card">
    <div class="stat-num" style="color:var(--cyan)">` + fmt.Sprintf("%d", len(data.Subdomains)) + `</div>
    <div class="stat-label">Subdomains</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:var(--green)">` + fmt.Sprintf("%d", len(data.LiveURLs)) + `</div>
    <div class="stat-label">Live URLs</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:var(--orange)">` + fmt.Sprintf("%d", len(data.Vulns)) + `</div>
    <div class="stat-label">Vulnerabilities</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:var(--red)">` + fmt.Sprintf("%d", critCount+highCount) + `</div>
    <div class="stat-label">Critical + High</div>
  </div>
</div>

<!-- Vulnerability Severity Breakdown -->
`)

	if len(data.Vulns) > 0 {
		sb.WriteString(`<div class="section">
<div class="section-title">🐛 Vulnerability Summary</div>
<div class="card">
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:16px;text-align:center">
`)
		for _, item := range []struct {
			label string
			count int
			color string
		}{
			{"Critical", critCount, "var(--critical)"},
			{"High", highCount, "var(--high)"},
			{"Medium", medCount, "var(--medium)"},
			{"Low", lowCount, "var(--low)"},
			{"Info", infoCount, "var(--info)"},
		} {
			sb.WriteString(fmt.Sprintf(`<div>
  <div style="font-size:28px;font-weight:800;color:%s">%d</div>
  <div style="color:var(--dim);font-size:12px">%s</div>
  <div class="progress-bar"><div class="progress-fill" style="width:%d%%;background:%s"></div></div>
</div>`, item.color, item.count, item.label,
				func() int {
					if len(data.Vulns) == 0 {
						return 0
					}
					return item.count * 100 / len(data.Vulns)
				}(), item.color))
		}
		sb.WriteString(`</div></div></div>`)

		// Vuln table
		sb.WriteString(`<div class="section">
<div class="section-title">🔍 Vulnerability Details</div>
<div class="card" style="padding:0;overflow:hidden">
<table>
<thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Tool</th></tr></thead>
<tbody>`)
		for _, v := range data.Vulns {
			badgeClass := "badge-info"
			switch v.Severity {
			case "critical":
				badgeClass = "badge-critical"
			case "high":
				badgeClass = "badge-high"
			case "medium":
				badgeClass = "badge-medium"
			case "low":
				badgeClass = "badge-low"
			}
			sb.WriteString(fmt.Sprintf(`<tr>
<td><span class="badge %s">%s</span></td>
<td>%s</td>
<td class="url">%s</td>
<td style="color:var(--dim)">%s</td>
</tr>`, badgeClass, html.EscapeString(v.Severity),
				html.EscapeString(v.Type),
				html.EscapeString(v.URL),
				html.EscapeString(v.Tool)))
		}
		sb.WriteString(`</tbody></table></div></div>`)
	}

	// Hotlist
	if len(data.Hotlist) > 0 {
		sb.WriteString(`<div class="section">
<div class="section-title">🎯 Hotlist — Top Risk Assets</div>
<div class="card">`)
		for _, e := range data.Hotlist {
			scoreClass := "score-low"
			if e.Score >= 80 {
				scoreClass = "score-high"
			} else if e.Score >= 50 {
				scoreClass = "score-med"
			}
			sb.WriteString(fmt.Sprintf(`<div class="hotlist-item">
<div class="hotlist-score %s">%.0f</div>
<div>
  <div style="font-weight:600;margin-bottom:4px">%s</div>
  <div class="url">%s</div>
  <div style="color:var(--dim);font-size:12px;margin-top:4px">%s</div>
</div>
</div>`, scoreClass, e.Score,
				html.EscapeString(e.Reason),
				html.EscapeString(e.Asset),
				html.EscapeString(e.Type)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Subdomains
	if len(data.Subdomains) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">🌐 Subdomains (%d)</div>
<div class="card">`, len(data.Subdomains)))
		for _, s := range data.Subdomains {
			sb.WriteString(fmt.Sprintf(`<div class="list-item">%s</div>`, html.EscapeString(s)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Technologies
	if len(data.Technologies) > 0 {
		sb.WriteString(`<div class="section">
<div class="section-title">🔧 Technology Stack</div>
<div class="card">`)
		for _, t := range data.Technologies {
			sb.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, html.EscapeString(t)))
		}
		if data.CMSDetected != "" {
			sb.WriteString(fmt.Sprintf(`<span class="tag" style="background:rgba(255,102,0,0.15);border-color:rgba(255,102,0,0.3);color:var(--orange)">CMS: %s</span>`,
				html.EscapeString(data.CMSDetected)))
		}
		sb.WriteString(`</div></div>`)
	}

	// WAF
	sb.WriteString(`<div class="section">
<div class="section-title">🛡️ WAF Detection</div>
<div class="card">`)
	if data.WAFDetected {
		vendor := data.WAFVendor
		if vendor == "" {
			vendor = "Unknown"
		}
		sb.WriteString(fmt.Sprintf(`<span class="waf-badge">⚠️ WAF Detected: %s</span>
<p style="color:var(--dim);margin-top:12px;font-size:13px">WAF bypass techniques may be required. Use --waf-bypass flags in dalfox/sqlmap.</p>`,
			html.EscapeString(vendor)))
	} else {
		sb.WriteString(`<span class="no-waf">✓ No WAF Detected — Direct testing possible</span>`)
	}
	sb.WriteString(`</div></div>`)

	// Open Ports
	if len(data.OpenPorts) > 0 {
		sb.WriteString(`<div class="section">
<div class="section-title">🔌 Open Ports</div>
<div class="card">`)
		for _, p := range data.OpenPorts {
			service := portService(p)
			sb.WriteString(fmt.Sprintf(`<span class="tag">%d/%s</span>`, p, service))
		}
		sb.WriteString(`</div></div>`)
	}

	// JS Secrets
	if len(data.JSSecrets) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">🔑 Exposed Secrets / API Keys (%d)</div>
<div class="card">`, len(data.JSSecrets)))
		for _, s := range data.JSSecrets {
			if len(s) > 120 {
				s = s[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf(`<div class="list-item" style="color:var(--yellow)">%s</div>`,
				html.EscapeString(s)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Vulnerable Libraries
	if len(data.VulnLibs) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">📦 Vulnerable JS Libraries (%d)</div>
<div class="card">`, len(data.VulnLibs)))
		for _, l := range data.VulnLibs {
			sb.WriteString(fmt.Sprintf(`<div class="list-item" style="color:var(--orange)">%s</div>`,
				html.EscapeString(l)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Cloud Buckets
	if len(data.CloudBuckets) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">☁️ Exposed Cloud Buckets (%d)</div>
<div class="card">`, len(data.CloudBuckets)))
		for _, b := range data.CloudBuckets {
			sb.WriteString(fmt.Sprintf(`<div class="list-item" style="color:var(--red)">%s</div>`,
				html.EscapeString(b)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Takeover Candidates
	if len(data.Takeovers) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">⚠️ Subdomain Takeover Candidates (%d)</div>
<div class="card">`, len(data.Takeovers)))
		for _, t := range data.Takeovers {
			sb.WriteString(fmt.Sprintf(`<div class="list-item" style="color:var(--critical)">⚠️ %s</div>`,
				html.EscapeString(t)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Diff section (if incremental)
	if data.Diff != nil && data.Diff.TotalNew > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">📊 Changes Since Last Scan</div>
<div class="card">
<p style="color:var(--dim);margin-bottom:16px">Compared to scan from %s</p>`,
			data.Diff.PrevRun.Format("2006-01-02 15:04:05")))

		if len(data.Diff.NewSubdomains) > 0 {
			sb.WriteString(fmt.Sprintf(`<p><span class="badge badge-new">+%d NEW</span> Subdomains</p>`,
				len(data.Diff.NewSubdomains)))
		}
		if len(data.Diff.NewVulns) > 0 {
			sb.WriteString(fmt.Sprintf(`<p style="margin-top:8px"><span class="badge badge-new">+%d NEW</span> Vulnerabilities</p>`,
				len(data.Diff.NewVulns)))
		}
		if len(data.Diff.NewSecrets) > 0 {
			sb.WriteString(fmt.Sprintf(`<p style="margin-top:8px"><span class="badge badge-new">+%d NEW</span> Secrets</p>`,
				len(data.Diff.NewSecrets)))
		}
		sb.WriteString(`</div></div>`)
	}

	// Tools
	if len(data.ToolsRun) > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="section">
<div class="section-title">🔧 Tools Executed (%d)</div>
<div class="card">`, len(data.ToolsRun)))
		for _, t := range data.ToolsRun {
			sb.WriteString(fmt.Sprintf(`<span class="tag" style="background:rgba(0,255,136,0.08);border-color:rgba(0,255,136,0.2);color:var(--green)">✓ %s</span>`,
				html.EscapeString(t)))
		}
		if len(data.ToolsFailed) > 0 {
			sb.WriteString(`<div style="margin-top:12px">`)
			for _, t := range data.ToolsFailed {
				sb.WriteString(fmt.Sprintf(`<span class="tag" style="background:rgba(255,68,68,0.08);border-color:rgba(255,68,68,0.2);color:var(--red)">✗ %s</span>`,
					html.EscapeString(t)))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`</div></div>`)
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`<div class="footer">
  Generated by <strong>CyberMind CLI</strong> &nbsp;|&nbsp;
  %s &nbsp;|&nbsp;
  For authorized security testing only
</div>

</div>
</body>
</html>`, time.Now().Format("2006-01-02 15:04:05")))

	return sb.String()
}

// portService returns a common service name for a port number.
func portService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 143: "imap",
		443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
		5432: "postgres", 6379: "redis", 8080: "http-alt",
		8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "tcp"
}
