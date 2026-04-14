// scope.go — Gap 2: Scope Awareness
// Parses program scope, expands wildcards, filters out-of-scope targets.
package brain

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// ScopeTarget represents a single testable target within a program's scope.
type ScopeTarget struct {
	Domain     string   `json:"domain"`
	URL        string   `json:"url,omitempty"`
	Type       string   `json:"type"`       // "domain", "url", "ip", "wildcard"
	InScope    bool     `json:"in_scope"`
	BountyMax  int      `json:"bounty_max"`
	Priority   int      `json:"priority"`   // 1-10, higher = more valuable
	Tags       []string `json:"tags"`       // "api", "admin", "payment", "auth"
}

// ProgramScope holds the full scope definition for a bug bounty program.
type ProgramScope struct {
	ProgramName  string        `json:"program_name"`
	Platform     string        `json:"platform"` // hackerone, bugcrowd
	Handle       string        `json:"handle"`
	InScope      []ScopeTarget `json:"in_scope"`
	OutScope     []ScopeTarget `json:"out_scope"`
	BountyTable  BountyTable   `json:"bounty_table"`
	LastFetched  time.Time     `json:"last_fetched"`
	ResponseTime int           `json:"avg_response_time_days"`
}

// BountyTable maps severity to bounty amounts.
type BountyTable struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ─── Scope Storage ────────────────────────────────────────────────────────────

func scopeFile(handle string) string {
	safe := strings.ReplaceAll(handle, "/", "_")
	return filepath.Join(brainDir(), "scopes", safe+".json")
}

// SaveScope persists a program scope.
func SaveScope(scope *ProgramScope) error {
	dir := filepath.Join(brainDir(), "scopes")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(scopeFile(scope.Handle), data, 0600)
}

// LoadScope loads a saved program scope.
func LoadScope(handle string) (*ProgramScope, error) {
	data, err := os.ReadFile(scopeFile(handle))
	if err != nil {
		return nil, err
	}
	var scope ProgramScope
	if err := json.Unmarshal(data, &scope); err != nil {
		return nil, err
	}
	return &scope, nil
}

// ─── Scope Intelligence ───────────────────────────────────────────────────────

// ExpandScope takes a scope definition and returns all testable targets.
// Handles wildcards, URL paths, IP ranges.
func ExpandScope(scope *ProgramScope, knownSubdomains []string) []ScopeTarget {
	var targets []ScopeTarget
	outScopeSet := buildOutScopeSet(scope.OutScope)

	for _, s := range scope.InScope {
		if !s.InScope {
			continue
		}
		switch s.Type {
		case "wildcard":
			// *.example.com → expand using known subdomains
			baseDomain := strings.TrimPrefix(s.Domain, "*.")
			for _, sub := range knownSubdomains {
				if strings.HasSuffix(sub, "."+baseDomain) || sub == baseDomain {
					if !isOutScope(sub, outScopeSet) {
						targets = append(targets, ScopeTarget{
							Domain:   sub,
							Type:     "domain",
							InScope:  true,
							Priority: prioritizeTarget(sub),
							Tags:     tagTarget(sub),
						})
					}
				}
			}
			// Always include the base domain itself
			if !isOutScope(baseDomain, outScopeSet) {
				targets = append(targets, ScopeTarget{
					Domain:   baseDomain,
					Type:     "domain",
					InScope:  true,
					Priority: prioritizeTarget(baseDomain),
					Tags:     tagTarget(baseDomain),
				})
			}
		case "domain":
			if !isOutScope(s.Domain, outScopeSet) {
				s.Priority = prioritizeTarget(s.Domain)
				s.Tags = tagTarget(s.Domain)
				targets = append(targets, s)
			}
		case "url":
			if !isOutScope(s.URL, outScopeSet) {
				s.Priority = prioritizeTarget(s.URL)
				targets = append(targets, s)
			}
		case "ip":
			if !isOutScope(s.Domain, outScopeSet) {
				targets = append(targets, s)
			}
		}
	}

	// Sort by priority descending
	sortByPriority(targets)
	return targets
}

// IsInScope checks if a URL/domain is within the program scope.
func IsInScope(urlOrDomain string, scope *ProgramScope) bool {
	outScopeSet := buildOutScopeSet(scope.OutScope)
	if isOutScope(urlOrDomain, outScopeSet) {
		return false
	}
	for _, s := range scope.InScope {
		if matchesScope(urlOrDomain, s) {
			return true
		}
	}
	return false
}

// PrioritizeTargets sorts targets by attack value.
// High-value: admin, api, auth, payment, internal
// Low-value: cdn, static, status, docs
func PrioritizeTargets(targets []ScopeTarget) []ScopeTarget {
	sortByPriority(targets)
	return targets
}

// GetHighValueTargets returns only high-priority targets (priority >= 7).
func GetHighValueTargets(targets []ScopeTarget) []ScopeTarget {
	var high []ScopeTarget
	for _, t := range targets {
		if t.Priority >= 7 {
			high = append(high, t)
		}
	}
	return high
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// prioritizeTarget scores a target by its attack value (1-10).
func prioritizeTarget(target string) int {
	lower := strings.ToLower(target)

	// Highest value — direct money/auth/admin
	highValue := []string{"admin", "api", "auth", "login", "payment", "pay",
		"checkout", "account", "dashboard", "internal", "corp", "vpn",
		"staging", "dev", "test", "beta", "portal", "manage", "console"}
	for _, kw := range highValue {
		if strings.Contains(lower, kw) {
			return 9
		}
	}

	// Medium-high value
	medHigh := []string{"app", "web", "mobile", "partner", "vendor",
		"upload", "file", "media", "user", "profile", "settings"}
	for _, kw := range medHigh {
		if strings.Contains(lower, kw) {
			return 7
		}
	}

	// Medium value
	medium := []string{"blog", "shop", "store", "mail", "email", "support"}
	for _, kw := range medium {
		if strings.Contains(lower, kw) {
			return 5
		}
	}

	// Low value — static/infra
	lowValue := []string{"cdn", "static", "assets", "img", "images",
		"status", "docs", "help", "www"}
	for _, kw := range lowValue {
		if strings.Contains(lower, kw) {
			return 2
		}
	}

	return 5 // default medium
}

// tagTarget assigns semantic tags to a target.
func tagTarget(target string) []string {
	lower := strings.ToLower(target)
	var tags []string

	tagMap := map[string]string{
		"api":      "api",
		"admin":    "admin",
		"auth":     "auth",
		"login":    "auth",
		"payment":  "payment",
		"pay":      "payment",
		"checkout": "payment",
		"internal": "internal",
		"staging":  "staging",
		"dev":      "dev",
		"test":     "test",
		"beta":     "beta",
		"upload":   "file-upload",
		"file":     "file-upload",
		"graphql":  "graphql",
		"grpc":     "grpc",
	}

	seen := make(map[string]bool)
	for kw, tag := range tagMap {
		if strings.Contains(lower, kw) && !seen[tag] {
			tags = append(tags, tag)
			seen[tag] = true
		}
	}
	return tags
}

func buildOutScopeSet(outScope []ScopeTarget) map[string]bool {
	set := make(map[string]bool)
	for _, s := range outScope {
		set[strings.ToLower(s.Domain)] = true
		if s.URL != "" {
			set[strings.ToLower(s.URL)] = true
		}
	}
	return set
}

func isOutScope(target string, outScopeSet map[string]bool) bool {
	lower := strings.ToLower(target)
	if outScopeSet[lower] {
		return true
	}
	// Check if any out-scope pattern matches
	for pattern := range outScopeSet {
		if strings.HasPrefix(pattern, "*.") {
			base := strings.TrimPrefix(pattern, "*.")
			if strings.HasSuffix(lower, "."+base) {
				return true
			}
		}
	}
	return false
}

func matchesScope(target string, scope ScopeTarget) bool {
	lower := strings.ToLower(target)
	scopeDomain := strings.ToLower(scope.Domain)

	switch scope.Type {
	case "wildcard":
		base := strings.TrimPrefix(scopeDomain, "*.")
		return strings.HasSuffix(lower, "."+base) || lower == base
	case "domain":
		return lower == scopeDomain || strings.HasSuffix(lower, "."+scopeDomain)
	case "url":
		return strings.HasPrefix(lower, strings.ToLower(scope.URL))
	case "ip":
		ip := net.ParseIP(target)
		if ip == nil {
			return false
		}
		_, network, err := net.ParseCIDR(scopeDomain)
		if err != nil {
			return target == scopeDomain
		}
		return network.Contains(ip)
	}
	return false
}

func sortByPriority(targets []ScopeTarget) {
	for i := 0; i < len(targets); i++ {
		for j := i + 1; j < len(targets); j++ {
			if targets[j].Priority > targets[i].Priority {
				targets[i], targets[j] = targets[j], targets[i]
			}
		}
	}
}

// FormatScopeReport returns a human-readable scope summary.
func FormatScopeReport(scope *ProgramScope, expanded []ScopeTarget) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  📋 Program: %s (%s)\n", scope.ProgramName, scope.Platform))
	sb.WriteString(fmt.Sprintf("  🎯 Testable targets: %d\n", len(expanded)))
	sb.WriteString(fmt.Sprintf("  💰 Bounty: Critical $%d | High $%d | Medium $%d\n",
		scope.BountyTable.Critical, scope.BountyTable.High, scope.BountyTable.Medium))

	high := GetHighValueTargets(expanded)
	if len(high) > 0 {
		sb.WriteString(fmt.Sprintf("  ⭐ High-value targets (%d):\n", len(high)))
		for i, t := range high {
			if i >= 5 {
				break
			}
			tags := ""
			if len(t.Tags) > 0 {
				tags = " [" + strings.Join(t.Tags, ",") + "]"
			}
			sb.WriteString(fmt.Sprintf("     %d. %s%s (priority: %d)\n", i+1, t.Domain, tags, t.Priority))
		}
	}
	return sb.String()
}
