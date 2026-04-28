// brain/crawling_brain.go — Crawling Intelligence Engine
// Teaches the AI brain WHEN, WHERE, and HOW to use each crawling type.
// Integrates with OMEGA, recon, and hunt modes for intelligent crawling decisions.
package brain

import (
	"fmt"
	"strings"
)

// CrawlingType represents a specific type of crawling technique.
type CrawlingType string

const (
	CrawlPassiveHistorical  CrawlingType = "passive_historical"   // gau, waybackurls, waymore
	CrawlActiveWeb          CrawlingType = "active_web"           // gospider, katana, hakrawler
	CrawlJSBased            CrawlingType = "js_based"             // katana -jc, cariddi -secrets
	CrawlHeadlessBrowser    CrawlingType = "headless_browser"     // katana -headless, playwright
	CrawlCertTransparency   CrawlingType = "cert_transparency"    // crt.sh, ctfr, tlsx -san
	CrawlDNSBrute           CrawlingType = "dns_brute"            // puredns, shuffledns, alterx
	CrawlGitHubCode         CrawlingType = "github_code"          // github-subdomains, trufflehog
	CrawlAPISwagger         CrawlingType = "api_swagger"          // nuclei -t apis/, swaggerspy
	CrawlSourceMap          CrawlingType = "source_map"           // sourcemapper
	CrawlInternetWide       CrawlingType = "internet_wide"        // uncover, shodan, censys
	CrawlURLDedup           CrawlingType = "url_dedup"            // uro
	CrawlJSWordlist         CrawlingType = "js_wordlist"          // getjswords
)

// CrawlingDecision holds the AI brain's decision about which crawling to use.
type CrawlingDecision struct {
	Type        CrawlingType
	Tools       []string
	Reason      string
	Priority    int    // 1=highest, 5=lowest
	Phase       string // recon, hunt, both
	Condition   string // when to use this
}

// CrawlingIntelligence holds all crawling knowledge for the AI brain.
type CrawlingIntelligence struct {
	Target      string
	TechStack   []string
	Decisions   []CrawlingDecision
	SPADetected bool
	APIDetected bool
	HasLogin    bool
	HasSwagger  bool
}

// AnalyzeCrawlingNeeds analyzes target and returns prioritized crawling decisions.
// This is the core intelligence — tells OMEGA/recon/hunt WHAT to crawl and HOW.
func AnalyzeCrawlingNeeds(target string, techStack []string, liveURLs []string, openPorts []int) CrawlingIntelligence {
	intel := CrawlingIntelligence{
		Target:    target,
		TechStack: techStack,
	}

	techStr := strings.ToLower(strings.Join(techStack, " "))
	urlStr := strings.ToLower(strings.Join(liveURLs, " "))

	// Detect SPA/JS-heavy frameworks
	intel.SPADetected = strings.Contains(techStr, "react") ||
		strings.Contains(techStr, "vue") ||
		strings.Contains(techStr, "angular") ||
		strings.Contains(techStr, "next") ||
		strings.Contains(techStr, "nuxt") ||
		strings.Contains(techStr, "svelte") ||
		strings.Contains(techStr, "ember")

	// Detect API presence
	intel.APIDetected = strings.Contains(urlStr, "/api/") ||
		strings.Contains(urlStr, "/v1/") ||
		strings.Contains(urlStr, "/v2/") ||
		strings.Contains(urlStr, "swagger") ||
		strings.Contains(urlStr, "openapi") ||
		strings.Contains(techStr, "rest") ||
		strings.Contains(techStr, "graphql")

	// Detect login
	intel.HasLogin = strings.Contains(urlStr, "login") ||
		strings.Contains(urlStr, "signin") ||
		strings.Contains(urlStr, "auth")

	// Detect Swagger
	intel.HasSwagger = strings.Contains(urlStr, "swagger") ||
		strings.Contains(urlStr, "api-docs") ||
		strings.Contains(urlStr, "openapi")

	// ── Build prioritized crawling decisions ──────────────────────────────

	// 1. ALWAYS: Passive historical crawling (zero noise, maximum coverage)
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlPassiveHistorical,
		Tools:     []string{"gau", "waybackurls", "waymore"},
		Reason:    "Always run first — discovers deleted endpoints, old parameters, historical attack surface with zero noise",
		Priority:  1,
		Phase:     "recon",
		Condition: "Always — run before any active crawling",
	})

	// 2. ALWAYS: Certificate Transparency (passive, finds subdomains)
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlCertTransparency,
		Tools:     []string{"crt.sh", "ctfr", "tlsx"},
		Reason:    "Passive subdomain discovery via SSL certificates — finds subdomains not in DNS",
		Priority:  1,
		Phase:     "recon",
		Condition: "Always — zero noise, high value",
	})

	// 3. ALWAYS: DNS brute-force (finds hidden subdomains)
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlDNSBrute,
		Tools:     []string{"puredns", "shuffledns", "alterx", "dnsx"},
		Reason:    "Discovers subdomains not in CT logs or passive sources — brute-force + permutations",
		Priority:  1,
		Phase:     "recon",
		Condition: "Always — run after passive to find remaining subdomains",
	})

	// 4. ALWAYS: Internet-wide asset discovery
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlInternetWide,
		Tools:     []string{"uncover", "shodan", "censys"},
		Reason:    "Finds ALL internet-facing assets of the org — ports, services, CVEs from Shodan/Censys/Fofa",
		Priority:  1,
		Phase:     "recon",
		Condition: "Always — run in parallel with DNS brute-force",
	})

	// 5. ALWAYS: Active web crawling (live site)
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlActiveWeb,
		Tools:     []string{"gospider", "katana", "hakrawler", "cariddi"},
		Reason:    "Discovers live endpoints, forms, JS files, sitemaps from the running application",
		Priority:  2,
		Phase:     "both",
		Condition: "After passive — crawl live site to find current attack surface",
	})

	// 6. ALWAYS: JS-based crawling
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlJSBased,
		Tools:     []string{"katana -jc", "cariddi -secrets", "subjs", "jsluice"},
		Reason:    "Extracts endpoints, API calls, secrets from JavaScript files — finds hidden routes",
		Priority:  2,
		Phase:     "hunt",
		Condition: "After active crawl — parse all JS files for hidden endpoints and secrets",
	})

	// 7. CONDITIONAL: Headless browser crawling (SPA sites)
	if intel.SPADetected {
		intel.Decisions = append(intel.Decisions, CrawlingDecision{
			Type:      CrawlHeadlessBrowser,
			Tools:     []string{"katana -headless"},
			Reason:    fmt.Sprintf("SPA detected (%s) — standard crawlers miss JS-rendered content; headless browser executes JS to find all routes", strings.Join(techStack[:min(3, len(techStack))], ", ")),
			Priority:  1, // HIGH priority for SPA
			Phase:     "hunt",
			Condition: "SPA/JS-heavy framework detected — REQUIRED for React/Vue/Angular/Next.js apps",
		})
	}

	// 8. CONDITIONAL: GitHub/code crawling
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlGitHubCode,
		Tools:     []string{"github-subdomains", "trufflehog", "gitleaks"},
		Reason:    "Finds subdomains in GitHub code, secrets in git history, API keys in source code",
		Priority:  2,
		Phase:     "recon",
		Condition: "Always — developers often commit secrets and internal URLs to GitHub",
	})

	// 9. CONDITIONAL: API/Swagger crawling
	if intel.APIDetected || intel.HasSwagger {
		intel.Decisions = append(intel.Decisions, CrawlingDecision{
			Type:      CrawlAPISwagger,
			Tools:     []string{"swaggerspy", "nuclei -t exposures/apis/"},
			Reason:    "API/Swagger detected — discovers undocumented endpoints, deprecated APIs, internal routes",
			Priority:  1, // HIGH priority for APIs
			Phase:     "hunt",
			Condition: "API or Swagger/OpenAPI detected — finds hidden admin endpoints",
		})
	}

	// 10. ALWAYS: Source map crawling
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlSourceMap,
		Tools:     []string{"sourcemapper"},
		Reason:    "Recovers original source code from .js.map files — finds internal paths, developer comments, secrets",
		Priority:  3,
		Phase:     "hunt",
		Condition: "After JS crawling — check for exposed source maps",
	})

	// 11. ALWAYS: URL deduplication
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlURLDedup,
		Tools:     []string{"uro"},
		Reason:    "Deduplicates and normalizes all crawled URLs — reduces noise before vulnerability scanning",
		Priority:  2,
		Phase:     "both",
		Condition: "After all URL collection — run before feeding to nuclei/dalfox/sqlmap",
	})

	// 12. ALWAYS: JS wordlist generation
	intel.Decisions = append(intel.Decisions, CrawlingDecision{
		Type:      CrawlJSWordlist,
		Tools:     []string{"getjswords"},
		Reason:    "Generates custom wordlist from JS content — finds domain-specific endpoints that generic wordlists miss",
		Priority:  3,
		Phase:     "hunt",
		Condition: "After JS crawling — use generated wordlist with ffuf/feroxbuster",
	})

	// Sort by priority
	for i := 0; i < len(intel.Decisions); i++ {
		for j := i + 1; j < len(intel.Decisions); j++ {
			if intel.Decisions[j].Priority < intel.Decisions[i].Priority {
				intel.Decisions[i], intel.Decisions[j] = intel.Decisions[j], intel.Decisions[i]
			}
		}
	}

	return intel
}

// FormatCrawlingPlan returns a human-readable crawling plan for the AI brain.
func FormatCrawlingPlan(intel CrawlingIntelligence) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n  🕷️  CRAWLING INTELLIGENCE — %s\n", intel.Target))

	if intel.SPADetected {
		sb.WriteString("  ⚡ SPA/JS Framework detected → HEADLESS BROWSER crawling required\n")
	}
	if intel.APIDetected {
		sb.WriteString("  🔌 API detected → SWAGGER/OPENAPI crawling required\n")
	}
	if intel.HasLogin {
		sb.WriteString("  🔐 Login detected → authenticated crawling recommended\n")
	}
	sb.WriteString("\n")

	sb.WriteString("  Crawling Pipeline (priority order):\n")
	for i, d := range intel.Decisions {
		sb.WriteString(fmt.Sprintf("  [%d] %s [%s]\n", i+1, string(d.Type), d.Phase))
		sb.WriteString(fmt.Sprintf("      Tools: %s\n", strings.Join(d.Tools, ", ")))
		sb.WriteString(fmt.Sprintf("      When: %s\n", d.Condition))
		sb.WriteString(fmt.Sprintf("      Why: %s\n\n", d.Reason))
	}

	return sb.String()
}

// GetCrawlingToolsForPhase returns the right crawling tools for a given phase.
// Used by OMEGA agentic brain to decide which crawlers to run.
func GetCrawlingToolsForPhase(phase string, techStack []string, liveURLs []string) []string {
	intel := AnalyzeCrawlingNeeds("", techStack, liveURLs, nil)
	var tools []string
	seen := map[string]bool{}

	for _, d := range intel.Decisions {
		if d.Phase == phase || d.Phase == "both" {
			for _, t := range d.Tools {
				// Extract just the tool name (before any flags)
				toolName := strings.Fields(t)[0]
				if !seen[toolName] {
					seen[toolName] = true
					tools = append(tools, toolName)
				}
			}
		}
	}
	return tools
}

// ShouldUseHeadlessCrawling returns true if headless browser crawling is needed.
// Called by OMEGA brain before starting hunt phase.
func ShouldUseHeadlessCrawling(techStack []string, liveURLs []string) (bool, string) {
	techStr := strings.ToLower(strings.Join(techStack, " "))
	urlStr := strings.ToLower(strings.Join(liveURLs, " "))

	spaFrameworks := []string{"react", "vue", "angular", "next", "nuxt", "svelte", "ember", "backbone"}
	for _, fw := range spaFrameworks {
		if strings.Contains(techStr, fw) {
			return true, fmt.Sprintf("%s framework detected — headless browser required for JS-rendered content", fw)
		}
	}

	// Check URL patterns that suggest SPA
	if strings.Contains(urlStr, "/#/") || strings.Contains(urlStr, "/app/") {
		return true, "SPA URL patterns detected (hash routing) — headless browser required"
	}

	return false, ""
}

// GetCrawlingSystemPrompt returns the crawling knowledge for AI system prompt.
// This teaches the AI brain about all crawling types and when to use them.
func GetCrawlingSystemPrompt() string {
	return `CRAWLING INTELLIGENCE — Complete Knowledge Base:

CRAWLING TYPES AND WHEN TO USE THEM:

1. PASSIVE/HISTORICAL (gau, waybackurls, waymore)
   → ALWAYS run FIRST — zero noise, finds deleted endpoints, old parameters
   → Phase: Recon Phase 2
   → Why: Discovers attack surface from archives without touching the target

2. CERTIFICATE TRANSPARENCY (crt.sh, ctfr, tlsx -san)
   → ALWAYS run — passive subdomain discovery via SSL certificates
   → Phase: Recon Phase 2
   → Why: Finds subdomains not in DNS, zero noise

3. DNS BRUTE-FORCE (puredns, shuffledns, alterx)
   → ALWAYS run after passive — finds remaining hidden subdomains
   → Phase: Recon Phase 2
   → Why: Brute-force + permutations finds subdomains CT logs miss

4. INTERNET-WIDE (uncover, shodan, censys)
   → ALWAYS run — finds ALL internet-facing assets
   → Phase: Recon Phase 1
   → Why: Discovers ports, services, CVEs from Shodan/Censys/Fofa

5. ACTIVE WEB CRAWLING (gospider, katana, hakrawler, cariddi)
   → ALWAYS run after passive — crawls live site
   → Phase: Recon Phase 2 + Hunt Phase 2
   → Why: Discovers live endpoints, forms, JS files, sitemaps

6. JS-BASED CRAWLING (katana -jc, cariddi -secrets, subjs, jsluice)
   → ALWAYS run — parses JS files for hidden endpoints
   → Phase: Hunt Phase 2
   → Why: SPA apps hide all routes in JS — standard crawlers miss them

7. HEADLESS BROWSER (katana -headless)
   → USE WHEN: React/Vue/Angular/Next.js/Nuxt/Svelte detected
   → Phase: Hunt Phase 2
   → Why: JS-rendered content invisible to standard crawlers; headless executes JS

8. GITHUB/CODE (github-subdomains, trufflehog, gitleaks)
   → ALWAYS run — finds secrets and subdomains in code
   → Phase: Recon Phase 2
   → Why: Developers commit secrets, internal URLs, API keys to GitHub

9. API/SWAGGER (swaggerspy, nuclei -t exposures/apis/)
   → USE WHEN: /api/, swagger, openapi detected in URLs
   → Phase: Hunt Phase 3
   → Why: Finds undocumented endpoints, deprecated APIs, internal routes

10. SOURCE MAP (sourcemapper)
    → ALWAYS try — recovers original source code
    → Phase: Hunt Phase 2
    → Why: .js.map files expose original source with internal paths and secrets

11. URL DEDUP (uro)
    → ALWAYS run AFTER all URL collection
    → Phase: Both
    → Why: Removes duplicate/similar URLs before vulnerability scanning

12. JS WORDLIST (getjswords)
    → ALWAYS run after JS crawling
    → Phase: Hunt Phase 2
    → Why: Domain-specific wordlist finds endpoints generic wordlists miss

CRAWLING DECISION RULES:
- SPA detected → MUST use headless browser (katana -headless)
- API detected → MUST use swaggerspy + nuclei API templates
- Login detected → Consider authenticated crawling with session cookies
- Large scope → Prioritize passive over active to avoid detection
- WAF detected → Use passive crawling first, then slow active crawling
- Quick mode → passive + CT logs only (no active crawling)
- Deep mode → all crawling types in parallel
- Overnight mode → all crawling + headless + authenticated`
}


