// brain/recon_brain.go — Dedicated Recon Mode AI Brain
// Manages the full recon pipeline intelligence:
// - Decides which recon phases to run based on target type
// - Adapts tool selection based on findings
// - Integrates all Tier 1/2/3 tool outputs
// - Generates actionable intelligence for hunt phase
package brain

import (
	"fmt"
	"strings"
	"time"
)

// ReconPhaseResult holds structured output from a recon phase.
type ReconPhaseResult struct {
	Phase       int
	ToolsRun    []string
	ToolsFailed []string
	Subdomains  []string
	LiveURLs    []string
	OpenPorts   []int
	Technologies []string
	WAFDetected bool
	WAFVendor   string
	Secrets     []string
	Emails      []string
	Buckets     []string
	Takeovers   []string
	VulnLibs    []string
	CMSType     string
	Duration    time.Duration
}

// ReconIntelligence is the full intelligence gathered from recon.
// Passed to hunt phase for targeted vulnerability testing.
type ReconIntelligence struct {
	Target          string
	TargetType      string // web, api, mobile, cloud, network
	Phases          []ReconPhaseResult
	TotalSubdomains int
	TotalLiveURLs   int
	TotalOpenPorts  int

	// High-value findings
	ExposedSecrets  []string
	ExposedEmails   []string
	CloudBuckets    []string
	TakeoverTargets []string
	VulnLibraries   []string
	CMSDetected     string
	WAFDetected     bool
	WAFVendor       string

	// Attack surface analysis
	AttackSurface   AttackSurface
	RecommendedFocus []string // vuln types to focus on in hunt
	Priority        string   // critical, high, medium, low
	Confidence      float64  // 0.0-1.0

	// Metadata
	ScanMode    string // quick, deep, overnight
	StartTime   time.Time
	EndTime     time.Time
	RunID       string
}

// AttackSurface categorizes the discovered attack surface.
type AttackSurface struct {
	HasLogin        bool
	HasAPI          bool
	HasGraphQL      bool
	HasFileUpload   bool
	HasPayment      bool
	HasOAuth        bool
	HasAdmin        bool
	HasWebSocket    bool
	HasMobileAPI    bool
	HasCloudStorage bool
	HasCICD         bool
	HasSMB          bool
	HasSNMP         bool
	HasLDAP         bool
	HasDatabase     bool
	ExposedServices []string
}

// AnalyzeReconIntelligence analyzes all recon findings and generates
// actionable intelligence for the hunt phase.
func AnalyzeReconIntelligence(target string, phases []ReconPhaseResult, techStack []string, liveURLs []string) ReconIntelligence {
	intel := ReconIntelligence{
		Target:    target,
		Phases:    phases,
		StartTime: time.Now(),
		RunID:     GenerateRunID(),
	}

	techStr := strings.ToLower(strings.Join(techStack, " "))
	urlStr := strings.ToLower(strings.Join(liveURLs, " "))

	// Aggregate findings from all phases
	seenSubs := map[string]bool{}
	seenURLs := map[string]bool{}
	seenPorts := map[int]bool{}

	for _, phase := range phases {
		for _, s := range phase.Subdomains {
			if !seenSubs[s] {
				seenSubs[s] = true
				intel.TotalSubdomains++
			}
		}
		for _, u := range phase.LiveURLs {
			if !seenURLs[u] {
				seenURLs[u] = true
				intel.TotalLiveURLs++
			}
		}
		for _, p := range phase.OpenPorts {
			if !seenPorts[p] {
				seenPorts[p] = true
				intel.TotalOpenPorts++
				intel.AttackSurface.ExposedServices = append(intel.AttackSurface.ExposedServices, fmt.Sprintf("%d", p))
			}
		}
		intel.ExposedSecrets = append(intel.ExposedSecrets, phase.Secrets...)
		intel.ExposedEmails = append(intel.ExposedEmails, phase.Emails...)
		intel.CloudBuckets = append(intel.CloudBuckets, phase.Buckets...)
		intel.TakeoverTargets = append(intel.TakeoverTargets, phase.Takeovers...)
		intel.VulnLibraries = append(intel.VulnLibraries, phase.VulnLibs...)
		if phase.WAFDetected {
			intel.WAFDetected = true
			intel.WAFVendor = phase.WAFVendor
		}
		if phase.CMSType != "" {
			intel.CMSDetected = phase.CMSType
		}
	}

	// Analyze attack surface from URLs and tech
	intel.AttackSurface = analyzeAttackSurface(urlStr, techStr, intel.TotalOpenPorts, phases)

	// Generate recommended focus areas
	intel.RecommendedFocus = generateReconFocus(intel, techStr, urlStr)

	// Calculate priority and confidence
	intel.Priority, intel.Confidence = calculateReconPriority(intel)

	intel.EndTime = time.Now()
	return intel
}

// analyzeAttackSurface determines what attack vectors are available.
func analyzeAttackSurface(urlStr, techStr string, portCount int, phases []ReconPhaseResult) AttackSurface {
	as := AttackSurface{}

	// URL-based detection
	as.HasLogin = strings.Contains(urlStr, "login") || strings.Contains(urlStr, "signin") ||
		strings.Contains(urlStr, "auth") || strings.Contains(urlStr, "account")
	as.HasAPI = strings.Contains(urlStr, "/api/") || strings.Contains(urlStr, "/v1/") ||
		strings.Contains(urlStr, "/v2/") || strings.Contains(urlStr, "/rest/") ||
		strings.Contains(techStr, "swagger") || strings.Contains(techStr, "openapi")
	as.HasGraphQL = strings.Contains(urlStr, "graphql") || strings.Contains(urlStr, "/gql") ||
		strings.Contains(techStr, "graphql")
	as.HasFileUpload = strings.Contains(urlStr, "upload") || strings.Contains(urlStr, "file") ||
		strings.Contains(urlStr, "attachment") || strings.Contains(urlStr, "import")
	as.HasPayment = strings.Contains(urlStr, "payment") || strings.Contains(urlStr, "checkout") ||
		strings.Contains(urlStr, "billing") || strings.Contains(urlStr, "cart") ||
		strings.Contains(urlStr, "stripe") || strings.Contains(urlStr, "paypal")
	as.HasOAuth = strings.Contains(urlStr, "oauth") || strings.Contains(urlStr, "authorize") ||
		strings.Contains(urlStr, "callback") || strings.Contains(urlStr, "openid")
	as.HasAdmin = strings.Contains(urlStr, "admin") || strings.Contains(urlStr, "dashboard") ||
		strings.Contains(urlStr, "manage") || strings.Contains(urlStr, "console") ||
		strings.Contains(urlStr, "panel") || strings.Contains(urlStr, "cms")
	as.HasWebSocket = strings.Contains(urlStr, "ws://") || strings.Contains(urlStr, "wss://") ||
		strings.Contains(techStr, "websocket") || strings.Contains(techStr, "socket.io")
	as.HasMobileAPI = strings.Contains(urlStr, "/mobile/") || strings.Contains(urlStr, "/app/") ||
		strings.Contains(urlStr, "/ios/") || strings.Contains(urlStr, "/android/")
	as.HasCloudStorage = strings.Contains(urlStr, "s3.amazonaws") || strings.Contains(urlStr, "blob.core.windows") ||
		strings.Contains(urlStr, "storage.googleapis") || strings.Contains(urlStr, "cloudfront")
	as.HasCICD = strings.Contains(urlStr, "jenkins") || strings.Contains(urlStr, "gitlab") ||
		strings.Contains(urlStr, "github") || strings.Contains(urlStr, "travis") ||
		strings.Contains(techStr, "jenkins") || strings.Contains(techStr, "gitlab")

	// Port-based detection
	for _, phase := range phases {
		for _, p := range phase.OpenPorts {
			switch p {
			case 445, 139:
				as.HasSMB = true
			case 161, 162:
				as.HasSNMP = true
			case 389, 636:
				as.HasLDAP = true
			case 3306, 5432, 1433, 27017, 6379:
				as.HasDatabase = true
			}
		}
	}

	return as
}

// generateReconFocus returns prioritized vuln types based on recon findings.
func generateReconFocus(intel ReconIntelligence, techStr, urlStr string) []string {
	var focus []string
	seen := map[string]bool{}

	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			focus = append(focus, f)
		}
	}

	// Critical findings first
	if len(intel.TakeoverTargets) > 0 {
		add("subdomain_takeover") // immediate win
	}
	if len(intel.ExposedSecrets) > 0 {
		add("secret_exposure") // immediate win
	}
	if len(intel.CloudBuckets) > 0 {
		add("cloud_bucket_exposure") // immediate win
	}
	if len(intel.VulnLibraries) > 0 {
		add("vulnerable_libraries") // known CVEs
	}

	// Attack surface based
	as := intel.AttackSurface
	if as.HasOAuth {
		add("oauth_misconfig") // high value
	}
	if as.HasGraphQL {
		add("graphql_introspection")
		add("graphql_idor")
	}
	if as.HasFileUpload {
		add("file_upload_rce")
	}
	if as.HasPayment {
		add("payment_logic")
		add("price_manipulation")
	}
	if as.HasAdmin {
		add("admin_bypass")
		add("auth_bypass")
	}
	if as.HasAPI {
		add("idor")
		add("mass_assignment")
		add("broken_object_auth")
	}
	if as.HasLogin {
		add("sqli")
		add("auth_bypass")
		add("credential_stuffing")
	}
	if as.HasSMB {
		add("smb_relay")
		add("smb_enum")
	}
	if as.HasDatabase {
		add("unauth_db_access")
	}

	// Tech-based focus
	techFocus := selectFocusByTech(techStr)
	for _, f := range strings.Split(techFocus, ",") {
		add(strings.TrimSpace(f))
	}

	// WAF bypass if WAF detected
	if intel.WAFDetected {
		add("waf_bypass")
	}

	// Always include these
	add("xss")
	add("ssrf")
	add("lfi")

	return focus
}

// calculateReconPriority determines how promising this target is.
func calculateReconPriority(intel ReconIntelligence) (string, float64) {
	score := 0.0

	// Immediate wins
	if len(intel.TakeoverTargets) > 0 {
		score += 0.4 // takeovers = guaranteed bounty
	}
	if len(intel.ExposedSecrets) > 0 {
		score += 0.3
	}
	if len(intel.CloudBuckets) > 0 {
		score += 0.2
	}

	// Attack surface richness
	as := intel.AttackSurface
	if as.HasOAuth {
		score += 0.15
	}
	if as.HasPayment {
		score += 0.15
	}
	if as.HasFileUpload {
		score += 0.1
	}
	if as.HasGraphQL {
		score += 0.1
	}
	if as.HasAdmin {
		score += 0.1
	}
	if as.HasAPI {
		score += 0.1
	}

	// Scale
	if intel.TotalSubdomains > 100 {
		score += 0.1 // large attack surface
	}
	if intel.TotalOpenPorts > 10 {
		score += 0.05
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	priority := "low"
	switch {
	case score >= 0.7:
		priority = "critical"
	case score >= 0.5:
		priority = "high"
	case score >= 0.3:
		priority = "medium"
	}

	return priority, score
}

// FormatReconIntelligence returns a human-readable intelligence report.
func FormatReconIntelligence(intel ReconIntelligence) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n  🧠 RECON INTELLIGENCE REPORT — %s\n", intel.Target))
	sb.WriteString(fmt.Sprintf("  Priority: %s (confidence: %.0f%%)\n\n",
		strings.ToUpper(intel.Priority), intel.Confidence*100))

	sb.WriteString(fmt.Sprintf("  📊 Attack Surface:\n"))
	sb.WriteString(fmt.Sprintf("     Subdomains: %d | Live URLs: %d | Open Ports: %d\n",
		intel.TotalSubdomains, intel.TotalLiveURLs, intel.TotalOpenPorts))

	if intel.WAFDetected {
		sb.WriteString(fmt.Sprintf("     WAF: %s detected — bypass techniques required\n", intel.WAFVendor))
	}
	if intel.CMSDetected != "" {
		sb.WriteString(fmt.Sprintf("     CMS: %s detected\n", intel.CMSDetected))
	}

	// Immediate wins
	if len(intel.TakeoverTargets) > 0 {
		sb.WriteString(fmt.Sprintf("\n  🎯 IMMEDIATE WINS:\n"))
		sb.WriteString(fmt.Sprintf("     ⚠️  %d subdomain takeover candidates!\n", len(intel.TakeoverTargets)))
		for _, t := range intel.TakeoverTargets[:minInt(3, len(intel.TakeoverTargets))] {
			sb.WriteString(fmt.Sprintf("        → %s\n", t))
		}
	}
	if len(intel.ExposedSecrets) > 0 {
		sb.WriteString(fmt.Sprintf("     🔑 %d exposed secrets/API keys!\n", len(intel.ExposedSecrets)))
	}
	if len(intel.CloudBuckets) > 0 {
		sb.WriteString(fmt.Sprintf("     ☁️  %d exposed cloud buckets!\n", len(intel.CloudBuckets)))
	}
	if len(intel.VulnLibraries) > 0 {
		sb.WriteString(fmt.Sprintf("     📦 %d vulnerable JS libraries!\n", len(intel.VulnLibraries)))
	}

	// Attack surface
	as := intel.AttackSurface
	sb.WriteString(fmt.Sprintf("\n  🔍 Attack Vectors Detected:\n"))
	vectors := []struct{ flag bool; name string }{
		{as.HasOAuth, "OAuth/OIDC"},
		{as.HasGraphQL, "GraphQL"},
		{as.HasFileUpload, "File Upload"},
		{as.HasPayment, "Payment/Checkout"},
		{as.HasAdmin, "Admin Panel"},
		{as.HasAPI, "REST API"},
		{as.HasLogin, "Login/Auth"},
		{as.HasWebSocket, "WebSocket"},
		{as.HasSMB, "SMB (445)"},
		{as.HasDatabase, "Exposed DB"},
		{as.HasCICD, "CI/CD"},
	}
	for _, v := range vectors {
		if v.flag {
			sb.WriteString(fmt.Sprintf("     ✓ %s\n", v.name))
		}
	}

	// Recommended focus
	if len(intel.RecommendedFocus) > 0 {
		sb.WriteString(fmt.Sprintf("\n  🎯 Hunt Focus (priority order):\n"))
		for i, f := range intel.RecommendedFocus {
			if i >= 8 {
				break
			}
			sb.WriteString(fmt.Sprintf("     %d. %s\n", i+1, f))
		}
	}

	return sb.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
