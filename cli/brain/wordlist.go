// wordlist.go — Smart Target-Aware Wordlist Generator
// Generates custom wordlists based on target intelligence:
// tech stack, company name, domain patterns, known endpoints, leaked data.
package brain

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// WordlistConfig controls wordlist generation.
type WordlistConfig struct {
	Target      string
	TechStack   []string
	CompanyName string
	Domain      string
	Type        string // "dirs", "params", "subdomains", "passwords", "api-endpoints"
	Size        int    // number of words
	OutputFile  string
}

// GenerateSmartWordlist creates a target-aware wordlist.
// It combines: AI-generated words + tech-specific patterns + known endpoints + mutations.
func GenerateSmartWordlist(cfg WordlistConfig) ([]string, error) {
	var words []string

	// 1. Base words from target domain
	words = append(words, extractDomainWords(cfg.Domain)...)

	// 2. Tech-stack specific words
	words = append(words, getTechStackWords(cfg.TechStack, cfg.Type)...)

	// 3. Common patterns for the type
	words = append(words, getTypePatterns(cfg.Type)...)

	// 4. Company-specific mutations
	if cfg.CompanyName != "" {
		words = append(words, generateCompanyMutations(cfg.CompanyName)...)
	}

	// 5. Year/date mutations
	words = append(words, generateDateMutations()...)

	// 6. Deduplicate and limit
	words = deduplicateWords(words)
	if cfg.Size > 0 && len(words) > cfg.Size {
		words = words[:cfg.Size]
	}

	// 7. Save to file if requested
	if cfg.OutputFile != "" {
		content := strings.Join(words, "\n")
		if err := os.WriteFile(cfg.OutputFile, []byte(content), 0644); err != nil {
			return words, fmt.Errorf("could not save wordlist: %v", err)
		}
	}

	return words, nil
}

// extractDomainWords extracts meaningful words from a domain name.
func extractDomainWords(domain string) []string {
	// Remove TLD
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	var words []string
	for _, p := range parts {
		words = append(words, p)
		// Split camelCase and hyphenated
		words = append(words, strings.Split(p, "-")...)
	}
	return words
}

// getTechStackWords returns wordlist entries specific to detected technologies.
func getTechStackWords(techStack []string, listType string) []string {
	var words []string

	techWords := map[string][]string{
		"wordpress": {
			"wp-admin", "wp-login.php", "wp-content", "wp-includes",
			"xmlrpc.php", "wp-json", "wp-cron.php", "wp-config.php",
			"wp-content/uploads", "wp-content/plugins", "wp-content/themes",
		},
		"laravel": {
			".env", "storage", "bootstrap/cache", "vendor",
			"artisan", "api/v1", "api/v2", "sanctum/csrf-cookie",
			"telescope", "horizon", "nova",
		},
		"django": {
			"admin/", "admin/login/", "api/", "static/",
			"media/", "__debug__/", "silk/", "api/schema/",
		},
		"rails": {
			"rails/info", "rails/mailers", "sidekiq",
			"api/v1", "api/v2", "graphql", "cable",
		},
		"nodejs": {
			"api/", "graphql", "socket.io", "health",
			"metrics", "swagger", "api-docs", "openapi.json",
		},
		"spring": {
			"actuator", "actuator/health", "actuator/env",
			"actuator/beans", "actuator/mappings", "swagger-ui.html",
			"v2/api-docs", "api/v1",
		},
		"php": {
			"phpinfo.php", "info.php", "test.php", "config.php",
			"admin.php", "login.php", "upload.php", "shell.php",
		},
		"graphql": {
			"graphql", "graphiql", "graphql/console",
			"api/graphql", "v1/graphql", "__schema",
		},
		"aws": {
			".aws/credentials", "aws-exports.js", "amplify",
			"s3", "cloudfront", "lambda",
		},
		"nginx": {
			"nginx_status", "status", "health", "metrics",
		},
		"apache": {
			"server-status", "server-info", ".htaccess",
			"cgi-bin/", "icons/",
		},
	}

	for _, tech := range techStack {
		techLower := strings.ToLower(tech)
		for key, techWordList := range techWords {
			if strings.Contains(techLower, key) {
				words = append(words, techWordList...)
			}
		}
	}

	return words
}

// getTypePatterns returns patterns specific to the wordlist type.
func getTypePatterns(listType string) []string {
	patterns := map[string][]string{
		"dirs": {
			"admin", "api", "v1", "v2", "v3", "auth", "login", "logout",
			"register", "signup", "dashboard", "panel", "console", "manage",
			"management", "internal", "private", "secret", "hidden", "backup",
			"config", "configuration", "settings", "setup", "install",
			"upload", "uploads", "files", "file", "media", "images", "img",
			"static", "assets", "js", "css", "fonts",
			"user", "users", "account", "accounts", "profile", "profiles",
			"payment", "payments", "billing", "invoice", "invoices",
			"order", "orders", "cart", "checkout",
			"search", "query", "data", "export", "import", "download",
			"report", "reports", "analytics", "stats", "statistics",
			"debug", "test", "dev", "development", "staging", "prod",
			"old", "new", "bak", "backup", "tmp", "temp", "cache",
			"logs", "log", "error", "errors",
			"health", "status", "ping", "metrics", "monitor",
			"swagger", "docs", "documentation", "api-docs", "openapi",
			"graphql", "graphiql", "playground",
			"webhook", "webhooks", "callback", "callbacks",
			"oauth", "oauth2", "sso", "saml", "token", "tokens",
			"reset", "forgot", "password", "passwords",
			"2fa", "mfa", "otp", "verify", "verification",
			"invite", "invites", "referral", "referrals",
			"admin/users", "admin/settings", "admin/logs",
			"api/v1/users", "api/v1/admin", "api/v2/users",
		},
		"params": {
			"id", "user_id", "userId", "uid", "account_id",
			"file", "filename", "path", "url", "redirect", "next", "return",
			"callback", "target", "dest", "destination",
			"page", "limit", "offset", "size", "count",
			"search", "query", "q", "keyword", "filter",
			"sort", "order", "orderby", "sortby",
			"token", "key", "api_key", "apikey", "secret",
			"email", "username", "user", "name",
			"action", "cmd", "command", "exec", "execute",
			"include", "require", "load", "template",
			"lang", "language", "locale", "format", "type",
			"debug", "test", "dev", "verbose",
			"ref", "source", "from", "to",
			"start", "end", "from_date", "to_date",
			"category", "tag", "label", "group",
			"parent_id", "parent", "child_id",
			"role", "permission", "scope", "access",
		},
		"subdomains": {
			"api", "admin", "app", "www", "mail", "email",
			"dev", "development", "staging", "test", "beta", "alpha",
			"internal", "intranet", "corp", "corporate",
			"vpn", "remote", "portal", "gateway",
			"auth", "login", "sso", "oauth",
			"cdn", "static", "assets", "media", "img",
			"blog", "docs", "help", "support", "status",
			"shop", "store", "checkout", "payment",
			"mobile", "m", "ios", "android",
			"api2", "api-v2", "v2", "v3",
			"dashboard", "panel", "console", "manage",
			"partner", "partners", "vendor", "vendors",
			"old", "legacy", "archive",
			"monitor", "metrics", "grafana", "kibana",
			"jenkins", "ci", "cd", "build",
			"git", "gitlab", "github", "bitbucket",
			"jira", "confluence", "wiki",
			"s3", "storage", "files", "upload",
			"smtp", "mx", "imap", "pop",
		},
		"api-endpoints": {
			"/api/v1/users", "/api/v1/admin", "/api/v1/config",
			"/api/v2/users", "/api/v2/admin",
			"/api/users/me", "/api/user/profile",
			"/api/admin/users", "/api/admin/settings",
			"/api/auth/login", "/api/auth/logout", "/api/auth/refresh",
			"/api/auth/register", "/api/auth/reset-password",
			"/api/payments", "/api/billing", "/api/invoices",
			"/api/orders", "/api/products", "/api/cart",
			"/api/search", "/api/export", "/api/import",
			"/api/webhooks", "/api/callbacks",
			"/api/health", "/api/status", "/api/metrics",
			"/api/debug", "/api/test",
			"/graphql", "/graphiql",
			"/swagger.json", "/openapi.json", "/api-docs",
		},
		"passwords": {
			"password", "Password", "PASSWORD",
			"password1", "Password1", "password123", "Password123",
			"admin", "Admin", "admin123", "Admin123",
			"123456", "12345678", "123456789",
			"qwerty", "Qwerty", "qwerty123",
			"letmein", "welcome", "Welcome1",
			"monkey", "dragon", "master",
			"iloveyou", "sunshine", "princess",
			"football", "baseball", "soccer",
			"superman", "batman", "spiderman",
		},
	}

	if words, ok := patterns[listType]; ok {
		return words
	}
	return patterns["dirs"] // default to dirs
}

// generateCompanyMutations creates company-specific password/wordlist mutations.
func generateCompanyMutations(company string) []string {
	company = strings.ToLower(strings.ReplaceAll(company, " ", ""))
	var words []string

	// Basic mutations
	words = append(words,
		company,
		strings.Title(company),
		strings.ToUpper(company),
		company+"123",
		company+"1234",
		company+"2024",
		company+"2025",
		company+"2026",
		company+"!",
		company+"@123",
		company+"#1",
		strings.Title(company)+"123",
		strings.Title(company)+"!",
		strings.Title(company)+"@2024",
		strings.Title(company)+"@2025",
		strings.Title(company)+"@2026",
		company+"_admin",
		company+"_api",
		company+"_dev",
		company+"_test",
		"admin_"+company,
		"api_"+company,
	)

	return words
}

// generateDateMutations creates date-based wordlist entries.
func generateDateMutations() []string {
	year := time.Now().Year()
	var words []string
	for y := year - 2; y <= year+1; y++ {
		words = append(words,
			fmt.Sprintf("%d", y),
			fmt.Sprintf("@%d", y),
			fmt.Sprintf("!%d", y),
			fmt.Sprintf("%d!", y),
		)
	}
	return words
}

// deduplicateWords removes duplicate entries from a wordlist.
func deduplicateWords(words []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, w := range words {
		if w != "" && !seen[w] {
			seen[w] = true
			unique = append(unique, w)
		}
	}
	return unique
}

// GenerateTargetWordlistFile generates a wordlist file for a target and returns the path.
func GenerateTargetWordlistFile(target string, listType string) (string, error) {
	mem := LoadTarget(target)

	// Extract company name from domain
	parts := strings.Split(target, ".")
	company := ""
	if len(parts) >= 2 {
		company = parts[len(parts)-2]
	}

	cfg := WordlistConfig{
		Target:      target,
		TechStack:   mem.TechStack,
		CompanyName: company,
		Domain:      target,
		Type:        listType,
		Size:        5000,
		OutputFile:  fmt.Sprintf("/tmp/cybermind_wordlist_%s_%s.txt", strings.ReplaceAll(target, ".", "_"), listType),
	}

	words, err := GenerateSmartWordlist(cfg)
	if err != nil {
		return "", err
	}

	// Also try to use cewl if available for web scraping
	if _, cewlErr := exec.LookPath("cewl"); cewlErr == nil {
		cewlOut, cewlRunErr := exec.Command("cewl",
			"https://"+target, "-d", "2", "-m", "5", "--lowercase").Output()
		if cewlRunErr == nil {
			cewlWords := strings.Split(string(cewlOut), "\n")
			words = append(words, cewlWords...)
			words = deduplicateWords(words)
		}
	}

	content := strings.Join(words, "\n")
	if err := os.WriteFile(cfg.OutputFile, []byte(content), 0644); err != nil {
		return "", err
	}

	return cfg.OutputFile, nil
}
