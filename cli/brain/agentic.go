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

// RecordSuccessfulPoC records a successful PoC to improve future prompts
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
func selectFocusByTech(techStr string) string {
	switch {
	case strings.Contains(techStr, "wordpress"):
		return "sqli,xss,rce"
	case strings.Contains(techStr, "graphql"):
		return "idor,ssrf,introspection"
	case strings.Contains(techStr, "node") || strings.Contains(techStr, "express"):
		return "ssrf,xss,prototype_pollution"
	case strings.Contains(techStr, "next") || strings.Contains(techStr, "react"):
		return "ssrf,xss,idor"
	case strings.Contains(techStr, "php"):
		return "sqli,lfi,rce"
	case strings.Contains(techStr, "laravel"):
		return "sqli,deserialization,ssrf"
	case strings.Contains(techStr, "asp.net") || strings.Contains(techStr, "iis"):
		return "sqli,xxe,deserialization"
	case strings.Contains(techStr, "java") || strings.Contains(techStr, "spring"):
		return "deserialization,ssrf,log4shell"
	case strings.Contains(techStr, "django") || strings.Contains(techStr, "flask"):
		return "ssti,ssrf,idor"
	case strings.Contains(techStr, "ruby") || strings.Contains(techStr, "rails"):
		return "sqli,deserialization,ssrf"
	case strings.Contains(techStr, "nginx") || strings.Contains(techStr, "apache"):
		return "path_traversal,ssrf,smuggling"
	case strings.Contains(techStr, "tomcat"):
		return "deserialization,rce,ssrf"
	case strings.Contains(techStr, "jenkins"):
		return "rce,ssrf,groovy_injection"
	case strings.Contains(techStr, "elasticsearch") || strings.Contains(techStr, "kibana"):
		return "unauth_access,ssrf,rce"
	case strings.Contains(techStr, "redis"):
		return "unauth_rce,ssrf"
	case strings.Contains(techStr, "mongodb"):
		return "nosqli,unauth_access"
	default:
		return "all"
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
