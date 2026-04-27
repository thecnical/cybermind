// Package brain - Agentic intelligence: memory-driven targeting, self-improving prompts
package brain

import (
"encoding/json"
"fmt"
"os"
"path/filepath"
"strings"
"time"
)

// SimilarTarget represents a target similar to one where bugs were found
type SimilarTarget struct {
Domain     string
Similarity float64
Reason     string
BugTypes   []string
}

// FindSimilarTargets finds targets in memory similar to currentTarget
func FindSimilarTargets(currentTarget string, limit int) []SimilarTarget {
dir := filepath.Join(brainDir(), "targets")
entries, err := os.ReadDir(dir)
if err != nil {
return nil
}

currentMem := LoadTarget(currentTarget)
currentTech := currentMem.TechStack
var results []SimilarTarget

for _, entry := range entries {
if entry.IsDir() {
continue
}
data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
if err != nil {
continue
}
var mem TargetMemory
if err := json.Unmarshal(data, &mem); err != nil {
continue
}
if mem.Target == currentTarget || len(mem.BugsFound) == 0 {
continue
}

score := 0.0
var reasons []string

// Tech stack overlap
techOverlap := 0
for _, t1 := range currentTech {
for _, t2 := range mem.TechStack {
if strings.EqualFold(t1, t2) {
techOverlap++
}
}
}
if len(currentTech) > 0 && techOverlap > 0 {
score += float64(techOverlap) / float64(len(currentTech)) * 0.5
reasons = append(reasons, fmt.Sprintf("same tech: %d overlap", techOverlap))
}

// Same WAF
if currentMem.WAFVendor != "" && mem.WAFVendor == currentMem.WAFVendor {
score += 0.2
reasons = append(reasons, "same WAF: "+mem.WAFVendor)
}

// Same TLD
aParts := strings.Split(currentTarget, ".")
bParts := strings.Split(mem.Target, ".")
if len(aParts) > 0 && len(bParts) > 0 && aParts[len(aParts)-1] == bParts[len(bParts)-1] {
score += 0.1
reasons = append(reasons, "same TLD")
}

// Bug count bonus
if len(mem.BugsFound) > 0 {
bonus := 0.1 * float64(len(mem.BugsFound))
if bonus > 0.3 {
bonus = 0.3
}
score += bonus
}

if score > 0.3 {
seen := map[string]bool{}
var bugTypes []string
for _, b := range mem.BugsFound {
if !seen[b.Type] {
seen[b.Type] = true
bugTypes = append(bugTypes, b.Type)
}
}
results = append(results, SimilarTarget{
Domain:     mem.Target,
Similarity: score,
Reason:     strings.Join(reasons, ", "),
BugTypes:   bugTypes,
})
}
}

// Sort by similarity descending
for i := 0; i < len(results); i++ {
for j := i + 1; j < len(results); j++ {
if results[j].Similarity > results[i].Similarity {
results[i], results[j] = results[j], results[i]
}
}
}

if limit > 0 && len(results) > limit {
return results[:limit]
}
return results
}

// GetBestAttackStrategy returns proven attack patterns for a target
func GetBestAttackStrategy(target string) []Pattern {
mem := LoadTarget(target)
if len(mem.PatternsWorked) > 0 {
return mem.PatternsWorked
}
// Fall back to similar targets
similar := FindSimilarTargets(target, 5)
var patterns []Pattern
seen := map[string]bool{}
for _, s := range similar {
simMem := LoadTarget(s.Domain)
for _, p := range simMem.PatternsWorked {
key := p.Type + "|" + p.Endpoint
if !seen[key] {
seen[key] = true
patterns = append(patterns, p)
}
}
}
return patterns
}

// GetLearnedPromptContext returns memory context to improve AI prompts
func GetLearnedPromptContext(target string) string {
mem := LoadTarget(target)
similar := FindSimilarTargets(target, 3)
var sb strings.Builder

if len(mem.BugsFound) > 0 {
sb.WriteString(fmt.Sprintf("PREVIOUS BUGS ON THIS TARGET (%d found):\n", len(mem.BugsFound)))
for _, b := range mem.BugsFound {
sb.WriteString(fmt.Sprintf("- %s [%s] at %s\n", b.Title, b.Severity, b.URL))
}
sb.WriteString("\n")
}

if len(mem.PatternsWorked) > 0 {
sb.WriteString("ATTACK PATTERNS THAT WORKED:\n")
for _, p := range mem.PatternsWorked {
sb.WriteString(fmt.Sprintf("- %s (%.0f%% success): %s\n", p.Type, p.SuccessRate*100, p.Description))
}
sb.WriteString("\n")
}

if len(mem.FalsePositives) > 0 {
n := len(mem.FalsePositives)
if n > 5 {
n = 5
}
sb.WriteString(fmt.Sprintf("KNOWN FALSE POSITIVES TO SKIP (%d):\n", len(mem.FalsePositives)))
for _, fp := range mem.FalsePositives[:n] {
sb.WriteString(fmt.Sprintf("- %s/%s: %s\n", fp.Tool, fp.Type, fp.Reason))
}
sb.WriteString("\n")
}

if len(similar) > 0 {
sb.WriteString("SIMILAR TARGETS WITH KNOWN BUGS:\n")
for _, s := range similar {
sb.WriteString(fmt.Sprintf("- %s (%.0f%% similar): bugs=%v, reason=%s\n",
s.Domain, s.Similarity*100, s.BugTypes, s.Reason))
}
sb.WriteString("\n")
}

return sb.String()
}

// RecordReconFTWFindings records reconftw-specific findings into brain memory.
// This teaches the brain which reconftw modules are most effective per target.
func RecordReconFTWFindings(target string, subdomainCount, urlCount, vulnCount int,
	secrets, emails, takeover, buckets []string, techStack []string, wafVendor string) {
	mem := LoadTarget(target)
	mem.mu.Lock()
	defer mem.mu.Unlock()

	// Record tech stack from reconftw
	techSeen := map[string]bool{}
	for _, t := range mem.TechStack {
		techSeen[t] = true
	}
	for _, t := range techStack {
		if !techSeen[t] {
			techSeen[t] = true
			mem.TechStack = append(mem.TechStack, t)
		}
	}

	// Record WAF
	if wafVendor != "" {
		mem.WAFDetected = true
		mem.WAFVendor = wafVendor
	}

	// Record takeover candidates as high-value findings
	for _, tc := range takeover {
		note := fmt.Sprintf("reconftw takeover candidate: %s", tc)
		if !strings.Contains(mem.Notes, tc) {
			if mem.Notes != "" {
				mem.Notes += "\n"
			}
			mem.Notes += note
		}
	}

	// Record exposed buckets
	for _, b := range buckets {
		note := fmt.Sprintf("reconftw cloud bucket: %s", b)
		if !strings.Contains(mem.Notes, b) {
			if mem.Notes != "" {
				mem.Notes += "\n"
			}
			mem.Notes += note
		}
	}

	// Record secrets as critical findings
	for _, s := range secrets {
		// Truncate for storage
		if len(s) > 80 {
			s = s[:80] + "..."
		}
		note := fmt.Sprintf("reconftw secret: %s", s)
		if !strings.Contains(mem.Notes, "reconftw secret") {
			if mem.Notes != "" {
				mem.Notes += "\n"
			}
			mem.Notes += note
		}
	}

	// Record reconftw effectiveness as a pattern
	if vulnCount > 0 {
		RecordPattern(target, "reconftw_vuln_scan",
			fmt.Sprintf("reconftw found %d vulns, %d subdomains, %d URLs", vulnCount, subdomainCount, urlCount),
			"", "")
	}

	mem.LastTested = time.Now()
	mem.RunCount++
	SaveTarget(mem)

	// Update global stats
	g := LoadGlobal()
	if g.TargetStats == nil {
		g.TargetStats = map[string]int{}
	}
	g.TargetStats[target] += vulnCount
	g.LastUpdated = time.Now()
	SaveGlobal(g)
}

// GetReconFTWRecommendation returns the recommended reconftw mode for a target
// based on past scan history and similar targets.
func GetReconFTWRecommendation(target string) (mode, reason string) {
	mem := LoadTarget(target)

	// If we've scanned before and found bugs, use deep mode
	if mem.RunCount > 0 && len(mem.BugsFound) > 0 {
		return "deep", fmt.Sprintf("previous scan found %d bugs — using deep mode for thorough coverage", len(mem.BugsFound))
	}

	// If we've scanned before and found nothing, try overnight for exhaustive coverage
	if mem.RunCount > 2 && len(mem.BugsFound) == 0 {
		return "overnight", "multiple scans found nothing — trying exhaustive overnight mode"
	}

	// Check similar targets
	similar := FindSimilarTargets(target, 3)
	for _, s := range similar {
		if s.Similarity > 0.7 && len(s.BugTypes) > 0 {
			return "deep", fmt.Sprintf("similar target %s had bugs — using deep mode", s.Domain)
		}
	}

	// Default: deep mode for first scan
	return "deep", "first scan — using deep mode for comprehensive coverage"
}
func RecordSuccessfulPoC(target, bugType, payload, endpoint, poc string) {
n := len(poc)
if n > 100 {
n = 100
}
RecordPattern(target, bugType+"_poc", "Successful PoC: "+poc[:n], payload, endpoint)

g := LoadGlobal()
for i, p := range g.BestPatterns {
if p.Type == bugType && p.Endpoint == endpoint {
g.BestPatterns[i].UsedCount++
g.BestPatterns[i].LastUsed = time.Now()
SaveGlobal(g)
return
}
}
g.BestPatterns = append(g.BestPatterns, Pattern{
Type:        bugType,
Description: "Global best pattern from " + target,
Payload:     payload,
Endpoint:    endpoint,
SuccessRate: 1.0,
UsedCount:   1,
LastUsed:    time.Now(),
})
SaveGlobal(g)
}

// SuggestNextAction returns the best next action based on current scan state.
// This is the brain's autonomous decision engine — called when AI is unavailable.
// Returns: action string, vuln focus, reason
func SuggestNextAction(
	target string,
	reconDone, huntDone, abhiDone bool,
	bugsFound int,
	bugTypes []string,
	technologies []string,
	wafDetected bool,
	mode string,
) (action, vulnFocus, reason string) {

	// Load memory for this target
	mem := LoadTarget(target)
	similar := FindSimilarTargets(target, 3)

	techStr := strings.ToLower(strings.Join(technologies, " "))

	// ── Memory-first: if we've been here before, use what worked ─────────
	if len(mem.PatternsWorked) > 0 && !reconDone {
		bestPattern := mem.PatternsWorked[0]
		return "recon", bestPattern.Type,
			fmt.Sprintf("Memory: %s worked %.0f%% of the time on this target — starting with targeted recon",
				bestPattern.Type, bestPattern.SuccessRate*100)
	}

	// ── Similar target intelligence ───────────────────────────────────────
	if len(similar) > 0 && !reconDone {
		for _, s := range similar {
			if len(s.BugTypes) > 0 && s.Similarity > 0.7 {
				return "recon", s.BugTypes[0],
					fmt.Sprintf("High similarity (%.0f%%) with %s which had %v bugs — targeting same vectors",
						s.Similarity*100, s.Domain, s.BugTypes)
			}
		}
	}

	// ── Quick mode: prioritize speed ─────────────────────────────────────
	if mode == "quick" {
		if !reconDone {
			return "recon", "all", "Quick mode: fast passive recon + subdomain enum"
		}
		if !huntDone {
			focus := selectFocusByTech(techStr)
			if len(mem.PatternsWorked) > 0 {
				focus = mem.PatternsWorked[0].Type
			}
			return "hunt", focus, fmt.Sprintf("Quick mode: tech-aware hunt focusing on %s", focus)
		}
		if bugsFound > 0 && !abhiDone {
			return "exploit", selectExploitByBugs(bugTypes),
				fmt.Sprintf("Quick mode: %d bugs found, exploiting immediately", bugsFound)
		}
		if bugsFound > 0 {
			return "poc", "all", "Quick mode: generating PoC for found bugs"
		}
		return "next_target", "all", "Quick mode: no bugs found, moving to next target"
	}

	// ── Deep/overnight mode: thorough coverage ────────────────────────────
	if !reconDone {
		return "recon", "all", "Phase 1: Full passive + active recon (subdomains, ports, tech fingerprint)"
	}

	if !huntDone {
		focus := selectFocusByTech(techStr)
		// Check if similar targets had specific bugs
		for _, s := range similar {
			if len(s.BugTypes) > 0 {
				focus = s.BugTypes[0]
				return "hunt", focus,
					fmt.Sprintf("Phase 2: Similar target %s had %s bugs — focusing hunt there", s.Domain, focus)
			}
		}
		return "hunt", focus, fmt.Sprintf("Phase 2: Full hunt with tech-aware focus: %s", focus)
	}

	if bugsFound > 0 && !abhiDone {
		focus := selectExploitByBugs(bugTypes)
		return "exploit", focus,
			fmt.Sprintf("Phase 3: Hunt found %d bugs (%v) — running Abhimanyu exploit phase on %s", bugsFound, bugTypes, focus)
	}

	if bugsFound > 0 && abhiDone {
		return "poc", "all", "Phase 4: Exploitation complete — generating PoC, report, and remediation guide"
	}

	// No bugs found after hunt — try deeper approaches
	if huntDone && bugsFound == 0 {
		if wafDetected {
			return "hunt", "waf_bypass",
				"WAF detected and blocking — retrying with adaptive bypass techniques (chunked encoding, unicode, null bytes)"
		}
		// Try novel attacks before giving up
		return "novel_attacks", "all",
			"Standard hunt found nothing — running novel attack engine (smuggling, cache poisoning, race conditions, XXE)"
	}

	return "done", "all", "All phases complete — generating final report"
}

// selectFocusByTech returns the best vuln focus based on tech stack
// Enhanced with 2025/2026 attack patterns
func selectFocusByTech(techStr string) string {
	switch {
	// CMS platforms — plugin/theme vulns
	case strings.Contains(techStr, "wordpress"):
		return "sqli,xss,rce,plugin_vuln"
	case strings.Contains(techStr, "drupal"):
		return "rce,sqli,xxe"
	case strings.Contains(techStr, "joomla"):
		return "sqli,rce,lfi"
	case strings.Contains(techStr, "magento"):
		return "sqli,rce,idor"
	// API frameworks
	case strings.Contains(techStr, "graphql"):
		return "idor,ssrf,introspection,batching_dos"
	case strings.Contains(techStr, "rest") || strings.Contains(techStr, "swagger"):
		return "idor,ssrf,auth_bypass,mass_assignment"
	// Node.js ecosystem
	case strings.Contains(techStr, "node") || strings.Contains(techStr, "express"):
		return "ssrf,xss,prototype_pollution,rce"
	case strings.Contains(techStr, "next") || strings.Contains(techStr, "react"):
		return "ssrf,xss,idor,open_redirect"
	case strings.Contains(techStr, "nuxt") || strings.Contains(techStr, "vue"):
		return "xss,ssrf,idor"
	// PHP frameworks
	case strings.Contains(techStr, "laravel"):
		return "sqli,deserialization,ssrf,debug_rce"
	case strings.Contains(techStr, "php"):
		return "sqli,lfi,rce,xxe"
	case strings.Contains(techStr, "symfony"):
		return "deserialization,ssrf,sqli"
	// Java ecosystem
	case strings.Contains(techStr, "spring"):
		return "deserialization,ssrf,log4shell,spel_injection"
	case strings.Contains(techStr, "java") || strings.Contains(techStr, "tomcat"):
		return "deserialization,rce,ssrf,log4shell"
	case strings.Contains(techStr, "struts"):
		return "rce,ognl_injection"
	// Python frameworks
	case strings.Contains(techStr, "django"):
		return "ssti,ssrf,idor,sqli"
	case strings.Contains(techStr, "flask"):
		return "ssti,ssrf,idor"
	case strings.Contains(techStr, "fastapi"):
		return "ssrf,idor,auth_bypass"
	// Ruby
	case strings.Contains(techStr, "rails") || strings.Contains(techStr, "ruby"):
		return "sqli,deserialization,ssrf,mass_assignment"
	// .NET
	case strings.Contains(techStr, "asp.net") || strings.Contains(techStr, "iis"):
		return "sqli,xxe,deserialization,viewstate_rce"
	// Web servers
	case strings.Contains(techStr, "nginx"):
		return "path_traversal,ssrf,smuggling,alias_traversal"
	case strings.Contains(techStr, "apache"):
		return "path_traversal,ssrf,mod_status"
	// Databases exposed
	case strings.Contains(techStr, "elasticsearch") || strings.Contains(techStr, "kibana"):
		return "unauth_access,ssrf,rce"
	case strings.Contains(techStr, "redis"):
		return "unauth_rce,ssrf"
	case strings.Contains(techStr, "mongodb"):
		return "nosqli,unauth_access"
	// Cloud/DevOps
	case strings.Contains(techStr, "jenkins"):
		return "rce,ssrf,groovy_injection,unauth_access"
	case strings.Contains(techStr, "kubernetes") || strings.Contains(techStr, "k8s"):
		return "ssrf,unauth_access,secret_exposure"
	case strings.Contains(techStr, "docker"):
		return "ssrf,container_escape,secret_exposure"
	// Mobile/API backends
	case strings.Contains(techStr, "firebase"):
		return "unauth_access,idor,data_exposure"
	case strings.Contains(techStr, "aws") || strings.Contains(techStr, "s3"):
		return "ssrf,bucket_exposure,iam_privesc"
	default:
		return "xss,sqli,ssrf,idor,lfi"
	}
}

// selectExploitByBugs returns the best Abhimanyu focus based on confirmed bugs
func selectExploitByBugs(bugTypes []string) string {
	if len(bugTypes) == 0 {
		return "all"
	}
	priority := []string{"rce", "sqli", "xss", "ssrf", "auth", "lfi"}
	bugSet := make(map[string]bool)
	for _, bt := range bugTypes {
		bugSet[strings.ToLower(bt)] = true
	}
	for _, p := range priority {
		if bugSet[p] {
			return p
		}
	}
	return bugTypes[0]
}
