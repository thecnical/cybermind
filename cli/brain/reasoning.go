// brain/reasoning.go - Structured AI Reasoning Engine
// Adds confidence-scored attack branch selection on top of the existing SelfThink engine.
// Uses the existing TargetProfile from self_think.go - no redeclaration.
package brain

import (
"fmt"
"math"
"sort"
"strings"
"time"
)

// AttackBranch represents one possible attack path with confidence scoring.
type AttackBranch struct {
ID         string
Name       string
Category   string
Confidence float64
Severity   string
Evidence   []string
Tools      []string
Flags      map[string]string
Tried      bool
Result     *BranchResult
CreatedAt  time.Time
UpdatedAt  time.Time
}

// BranchResult holds the outcome of executing a branch.
type BranchResult struct {
Success         bool
Findings        int
RawOutput       string
ConfidenceDelta float64
Duration        time.Duration
Error           string
}

// DecisionNode is one step in the reasoning tree audit trail.
type DecisionNode struct {
Question   string
Answer     string
Confidence float64
ChosenPath string
Reasoning  string
Timestamp  time.Time
}

// ReasoningSession tracks the full decision history for one target.
type ReasoningSession struct {
Target        string
Mode          string
Nodes         []DecisionNode
Branches      []*AttackBranch
Executed      []*AttackBranch
StartTime     time.Time
Iteration     int
MaxIter       int
MinConfidence float64
}

// NewReasoningSession creates a new session for a target.
func NewReasoningSession(target, mode string) *ReasoningSession {
maxIter := 5
minConf := 0.25
switch mode {
case "stealth":
maxIter = 3
minConf = 0.45
case "full":
maxIter = 8
minConf = 0.15
}
return &ReasoningSession{
Target:        target,
Mode:          mode,
StartTime:     time.Now(),
MaxIter:       maxIter,
MinConfidence: minConf,
}
}

// BuildBranchesFromProfile generates scored attack branches from a TargetProfile.
// Uses the existing TargetProfile struct from self_think.go.
func BuildBranchesFromProfile(profile TargetProfile) []*AttackBranch {
var branches []*AttackBranch

techStr := strings.ToLower(strings.Join(profile.TechStack, " "))
urlStr := strings.ToLower(strings.Join(profile.LiveURLs, " "))

hasLogin := strings.Contains(urlStr, "login") || strings.Contains(urlStr, "signin") ||
strings.Contains(urlStr, "auth") || strings.Contains(urlStr, "password")
hasAPI := strings.Contains(urlStr, "/api/") || strings.Contains(techStr, "rest") ||
strings.Contains(techStr, "graphql")
hasOAuth := len(profile.OAuthURLs) > 0 || strings.Contains(urlStr, "oauth") ||
strings.Contains(urlStr, "authorize")
hasPayment := strings.Contains(urlStr, "payment") || strings.Contains(urlStr, "checkout") ||
strings.Contains(urlStr, "cart") || strings.Contains(urlStr, "billing")
hasUpload := strings.Contains(urlStr, "upload") || strings.Contains(urlStr, "file") ||
strings.Contains(urlStr, "attachment")
hasGraphQL := strings.Contains(techStr, "graphql") || strings.Contains(urlStr, "graphql")

if hasLogin {
branches = append(branches,
&AttackBranch{
ID:         "auth-bypass",
Name:       "Authentication Bypass (SQLi, NoSQLi, Logic)",
Category:   "auth",
Confidence: boostConf(0.60, techStr, []string{"php", "mysql", "laravel"}),
Severity:   "critical",
Evidence:   []string{"Login endpoint detected"},
Tools:      []string{"sqlmap", "dalfox"},
Flags:      map[string]string{"sqlmap": "--level=3 --risk=2 --batch"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "auth-brute",
Name:       "Credential Brute Force / Stuffing",
Category:   "auth",
Confidence: 0.45,
Severity:   "high",
Evidence:   []string{"Login endpoint detected"},
Tools:      []string{"hydra", "ffuf"},
Flags:      map[string]string{"ffuf": "-w /usr/share/wordlists/rockyou.txt -mc 200,302"},
CreatedAt:  time.Now(),
},
)
}

if hasOAuth {
branches = append(branches, &AttackBranch{
ID:         "oauth-attacks",
Name:       "OAuth/OIDC Misconfiguration (state, redirect_uri, PKCE)",
Category:   "auth",
Confidence: 0.72,
Severity:   "critical",
Evidence:   []string{"OAuth endpoint detected"},
Tools:      []string{"cybermind-oauth"},
CreatedAt:  time.Now(),
})
}

if hasAPI {
branches = append(branches,
&AttackBranch{
ID:         "api-idor",
Name:       "IDOR / Broken Object Level Authorization",
Category:   "web",
Confidence: boostConf(0.70, techStr, []string{"api", "rest", "node"}),
Severity:   "high",
Evidence:   []string{"API with ID parameters detected"},
Tools:      []string{"cybermind-bizlogic"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "api-fuzz",
Name:       "API Endpoint Fuzzing (hidden routes, verb tampering)",
Category:   "web",
Confidence: 0.65,
Severity:   "high",
Evidence:   []string{"API endpoints detected"},
Tools:      []string{"ffuf", "nuclei"},
Flags:      map[string]string{"ffuf": "-w /usr/share/seclists/Discovery/Web-Content/api/objects.txt"},
CreatedAt:  time.Now(),
},
)
}

if hasGraphQL {
branches = append(branches, &AttackBranch{
ID:         "graphql-introspection",
Name:       "GraphQL Introspection + IDOR + Batching DoS",
Category:   "web",
Confidence: 0.78,
Severity:   "high",
Evidence:   []string{"GraphQL endpoint detected"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-t graphql"},
CreatedAt:  time.Now(),
})
}

if hasUpload {
branches = append(branches, &AttackBranch{
ID:         "file-upload",
Name:       "Malicious File Upload (RCE, SSRF, XSS via SVG)",
Category:   "web",
Confidence: 0.68,
Severity:   "critical",
Evidence:   []string{"File upload endpoint detected"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-t file-upload"},
CreatedAt:  time.Now(),
})
}

if hasPayment {
branches = append(branches, &AttackBranch{
ID:         "payment-logic",
Name:       "Payment / Business Logic Manipulation",
Category:   "logic",
Confidence: 0.75,
Severity:   "critical",
Evidence:   []string{"Payment/checkout flow detected"},
Tools:      []string{"cybermind-bizlogic"},
CreatedAt:  time.Now(),
})
}

// Port-based branches
for _, port := range profile.OpenPorts {
switch port {
case 6379:
branches = append(branches, &AttackBranch{
ID:         "redis-unauth",
Name:       "Redis Unauthenticated Access (RCE via config write)",
Category:   "network",
Confidence: 0.82,
Severity:   "critical",
Evidence:   []string{"Redis port 6379 open"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-t redis"},
CreatedAt:  time.Now(),
})
case 27017:
branches = append(branches, &AttackBranch{
ID:         "mongo-unauth",
Name:       "MongoDB Unauthenticated Access",
Category:   "network",
Confidence: 0.78,
Severity:   "critical",
Evidence:   []string{"MongoDB port 27017 open"},
Tools:      []string{"nuclei"},
CreatedAt:  time.Now(),
})
case 9200:
branches = append(branches, &AttackBranch{
ID:         "elastic-unauth",
Name:       "Elasticsearch Unauthenticated Access",
Category:   "network",
Confidence: 0.85,
Severity:   "critical",
Evidence:   []string{"Elasticsearch port 9200 open"},
Tools:      []string{"nuclei"},
CreatedAt:  time.Now(),
})
case 3306:
branches = append(branches, &AttackBranch{
ID:         "mysql-exposed",
Name:       "MySQL Exposed / Weak Credentials",
Category:   "network",
Confidence: 0.62,
Severity:   "critical",
Evidence:   []string{"MySQL port 3306 open"},
Tools:      []string{"hydra", "nuclei"},
CreatedAt:  time.Now(),
})
}
}

// WAF bypass branch if WAF detected
if profile.WAFDetected {
branches = append(branches, &AttackBranch{
ID:         "waf-bypass",
Name:       fmt.Sprintf("WAF Bypass (%s) - adaptive tamper selection", profile.WAFVendor),
Category:   "evasion",
Confidence: 0.60,
Severity:   "high",
Evidence:   []string{fmt.Sprintf("WAF detected: %s", profile.WAFVendor)},
Tools:      []string{"sqlmap", "dalfox"},
Flags:      map[string]string{"sqlmap": "--tamper=space2comment,randomcase,urlencode"},
CreatedAt:  time.Now(),
})
}

// Always-run branches
branches = append(branches,
&AttackBranch{
ID:         "nuclei-full",
Name:       "Nuclei Full Template Scan (critical+high+medium)",
Category:   "web",
Confidence: 0.70,
Severity:   "high",
Evidence:   []string{"HTTP service detected"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-severity critical,high,medium -rate-limit 150"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "xss-scan",
Name:       "Reflected/Stored XSS (dalfox)",
Category:   "web",
Confidence: 0.60,
Severity:   "medium",
Evidence:   []string{"Web application detected"},
Tools:      []string{"dalfox"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "sqli-scan",
Name:       "SQL Injection (sqlmap)",
Category:   "web",
Confidence: 0.55,
Severity:   "critical",
Evidence:   []string{"Web application with parameters"},
Tools:      []string{"sqlmap"},
Flags:      map[string]string{"sqlmap": "--level=3 --risk=2 --batch --random-agent"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "secrets-scan",
Name:       "Exposed Secrets / API Keys in JS/HTML",
Category:   "web",
Confidence: 0.65,
Severity:   "high",
Evidence:   []string{"Web application detected"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-t exposures,tokens"},
CreatedAt:  time.Now(),
},
&AttackBranch{
ID:         "smuggling",
Name:       "HTTP Request Smuggling (CL.TE / TE.CL)",
Category:   "web",
Confidence: 0.50,
Severity:   "high",
Evidence:   []string{"HTTP/1.1 service detected"},
Tools:      []string{"nuclei"},
Flags:      map[string]string{"nuclei": "-t http-smuggling"},
CreatedAt:  time.Now(),
},
)

// Boost confidence for branches matching past successful patterns
for _, pattern := range profile.Patterns {
if pattern.SuccessRate > 0.5 {
for _, b := range branches {
if strings.Contains(strings.ToLower(b.Name), strings.ToLower(pattern.Type)) {
b.Confidence = math.Min(0.95, b.Confidence+pattern.SuccessRate*0.15)
b.Evidence = append(b.Evidence, fmt.Sprintf("Past success rate: %.0f%%", pattern.SuccessRate*100))
}
}
}
}

sort.Slice(branches, func(i, j int) bool {
return branches[i].Confidence > branches[j].Confidence
})

return branches
}

// SelectNextBranch picks the highest-confidence untried branch above threshold.
func (s *ReasoningSession) SelectNextBranch() *AttackBranch {
for _, b := range s.Branches {
if !b.Tried && b.Confidence >= s.MinConfidence {
return b
}
}
return nil
}

// RecordDecision logs a reasoning step to the audit trail.
func (s *ReasoningSession) RecordDecision(question, answer, reasoning string, confidence float64, chosen string) {
s.Nodes = append(s.Nodes, DecisionNode{
Question:   question,
Answer:     answer,
Confidence: confidence,
ChosenPath: chosen,
Reasoning:  reasoning,
Timestamp:  time.Now(),
})
}

// UpdateConfidence re-scores branches after a result comes in.
func (s *ReasoningSession) UpdateConfidence(branch *AttackBranch, result BranchResult) {
branch.Tried = true
branch.Result = &result
branch.UpdatedAt = time.Now()

if result.Success && result.Findings > 0 {
for _, b := range s.Branches {
if !b.Tried && b.Category == branch.Category {
b.Confidence = math.Min(0.95, b.Confidence+0.12)
}
}
s.RecordDecision(
fmt.Sprintf("Branch %q succeeded with %d findings", branch.Name, result.Findings),
"boost related branches",
fmt.Sprintf("Category %q confirmed vulnerable - raising confidence for related paths", branch.Category),
branch.Confidence,
branch.ID,
)
} else {
for _, b := range s.Branches {
if !b.Tried && b.Category == branch.Category {
b.Confidence = math.Max(0.0, b.Confidence-0.08)
}
}
}
sort.Slice(s.Branches, func(i, j int) bool {
return s.Branches[i].Confidence > s.Branches[j].Confidence
})
}

// ShouldContinue returns true if the session should keep running.
func (s *ReasoningSession) ShouldContinue() bool {
if s.Iteration >= s.MaxIter {
return false
}
for _, b := range s.Branches {
if !b.Tried && b.Confidence >= s.MinConfidence {
return true
}
}
return false
}

// ReasoningSummary returns a human-readable reasoning summary.
func (s *ReasoningSession) ReasoningSummary() string {
var sb strings.Builder
sb.WriteString(fmt.Sprintf("\n  REASONING SUMMARY - %s\n", s.Target))
sb.WriteString(fmt.Sprintf("  Mode: %s | Iterations: %d/%d | Duration: %s\n",
s.Mode, s.Iteration, s.MaxIter, time.Since(s.StartTime).Round(time.Second)))
sb.WriteString(fmt.Sprintf("  Branches evaluated: %d | Executed: %d\n\n",
len(s.Branches), len(s.Executed)))

if len(s.Nodes) > 0 {
sb.WriteString("  Decision trail:\n")
for i, n := range s.Nodes {
sb.WriteString(fmt.Sprintf("  [%d] %s -> %s (conf=%.2f)\n",
i+1, n.Question, n.Reasoning, n.Confidence))
}
sb.WriteString("\n")
}

sb.WriteString("  Branch scores:\n")
for _, b := range s.Branches {
status := "pending"
if b.Tried {
if b.Result != nil && b.Result.Success {
status = fmt.Sprintf("FOUND %d findings", b.Result.Findings)
} else {
status = "no findings"
}
}
bar := reasoningConfBar(b.Confidence)
sb.WriteString(fmt.Sprintf("  %s %.0f%% %-48s %s\n",
bar, b.Confidence*100, b.Name, status))
}
return sb.String()
}

// FormatBranchPlan returns a human-readable attack plan.
func FormatBranchPlan(branches []*AttackBranch) string {
var sb strings.Builder
sb.WriteString("\n  ATTACK PLAN (confidence-ranked)\n")
sb.WriteString("  " + strings.Repeat("-", 60) + "\n\n")
for i, b := range branches {
bar := reasoningConfBar(b.Confidence)
sb.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, b.Name))
sb.WriteString(fmt.Sprintf("      %s %.0f%%  Severity: %s\n",
bar, b.Confidence*100, strings.ToUpper(b.Severity)))
sb.WriteString(fmt.Sprintf("      Tools: %s\n", strings.Join(b.Tools, ", ")))
if len(b.Evidence) > 0 {
sb.WriteString(fmt.Sprintf("      Evidence: %s\n", strings.Join(b.Evidence, "; ")))
}
sb.WriteString("\n")
}
return sb.String()
}

// TopBranches returns the N highest-confidence branches.
func TopBranches(branches []*AttackBranch, n int) []*AttackBranch {
if n > len(branches) {
n = len(branches)
}
return branches[:n]
}

func boostConf(base float64, techStr string, signals []string) float64 {
score := base
for _, sig := range signals {
if strings.Contains(techStr, sig) {
score += 0.05
}
}
return math.Min(0.95, score)
}

func reasoningConfBar(conf float64) string {
filled := int(conf * 10)
if filled > 10 {
filled = 10
}
bar := strings.Repeat("#", filled) + strings.Repeat(".", 10-filled)
return "[" + bar + "]"
}
