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
