// brain/knowledge_graph.go — Knowledge Graph for CyberMind
// Stores relationships between targets, vulnerabilities, tech stacks, and attack paths.
// Persisted as JSON at ~/.cybermind/brain/graph.json
// Used by OMEGA to make smarter decisions based on cross-target intelligence.
package brain

import (
"encoding/json"
"fmt"
"os"
"path/filepath"
"strings"
"time"
)

// NodeType identifies what kind of entity a graph node represents
type NodeType string

const (
NodeTarget  NodeType = "target"
NodeVuln    NodeType = "vuln"
NodeTech    NodeType = "tech"
NodeTool    NodeType = "tool"
NodePayload NodeType = "payload"
NodeCVE     NodeType = "cve"
)

// GraphNode is a vertex in the knowledge graph
type GraphNode struct {
ID         string            `json:"id"`
Type       NodeType          `json:"type"`
Label      string            `json:"label"`
Properties map[string]string `json:"properties,omitempty"`
CreatedAt  time.Time         `json:"created_at"`
UpdatedAt  time.Time         `json:"updated_at"`
}

// EdgeType identifies the relationship between two nodes
type EdgeType string

const (
EdgeHasVuln      EdgeType = "has_vuln"       // target → vuln
EdgeUsesTech     EdgeType = "uses_tech"       // target → tech
EdgeExploitedBy  EdgeType = "exploited_by"    // vuln → tool
EdgeLeadsTo      EdgeType = "leads_to"        // vuln → vuln (chain)
EdgeSimilarTo    EdgeType = "similar_to"      // target → target
EdgeMappedToCVE  EdgeType = "mapped_to_cve"   // vuln → cve
EdgeBypassedWith EdgeType = "bypassed_with"   // waf → payload
)

// GraphEdge is a directed relationship between two nodes
type GraphEdge struct {
ID         string            `json:"id"`
From       string            `json:"from"`
To         string            `json:"to"`
Type       EdgeType          `json:"type"`
Weight     float64           `json:"weight"` // confidence/strength 0-1
Properties map[string]string `json:"properties,omitempty"`
CreatedAt  time.Time         `json:"created_at"`
}

// KnowledgeGraph is the full graph structure
type KnowledgeGraph struct {
Nodes     map[string]*GraphNode `json:"nodes"`
Edges     []*GraphEdge          `json:"edges"`
UpdatedAt time.Time             `json:"updated_at"`
}

// graphFile returns the path to the knowledge graph JSON
func graphFile() string {
home, _ := os.UserHomeDir()
return filepath.Join(home, ".cybermind", "brain", "graph.json")
}

// LoadGraph loads the knowledge graph from disk
func LoadGraph() *KnowledgeGraph {
g := &KnowledgeGraph{
Nodes: make(map[string]*GraphNode),
Edges: []*GraphEdge{},
}
data, err := os.ReadFile(graphFile())
if err != nil {
return g
}
json.Unmarshal(data, g)
return g
}

// SaveGraph persists the knowledge graph to disk
func SaveGraph(g *KnowledgeGraph) error {
g.UpdatedAt = time.Now()
dir := filepath.Dir(graphFile())
os.MkdirAll(dir, 0700)
data, err := json.MarshalIndent(g, "", "  ")
if err != nil {
return err
}
return os.WriteFile(graphFile(), data, 0600)
}

// AddNode adds or updates a node in the graph
func (g *KnowledgeGraph) AddNode(id string, nodeType NodeType, label string, props map[string]string) *GraphNode {
if existing, ok := g.Nodes[id]; ok {
existing.UpdatedAt = time.Now()
if props != nil {
for k, v := range props {
existing.Properties[k] = v
}
}
return existing
}
node := &GraphNode{
ID:         id,
Type:       nodeType,
Label:      label,
Properties: props,
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
}
if node.Properties == nil {
node.Properties = make(map[string]string)
}
g.Nodes[id] = node
return node
}

// AddEdge adds a directed edge between two nodes
func (g *KnowledgeGraph) AddEdge(from, to string, edgeType EdgeType, weight float64, props map[string]string) {
// Check for duplicate
for _, e := range g.Edges {
if e.From == from && e.To == to && e.Type == edgeType {
e.Weight = weight
e.UpdatedAt()
return
}
}
edge := &GraphEdge{
ID:         fmt.Sprintf("%s_%s_%s", from, edgeType, to),
From:       from,
To:         to,
Type:       edgeType,
Weight:     weight,
Properties: props,
CreatedAt:  time.Now(),
}
g.Edges = append(g.Edges, edge)
}

// UpdatedAt is a helper method on GraphEdge
func (e *GraphEdge) UpdatedAt() {
// edges don't have UpdatedAt field — just update weight
}

// RecordTargetVuln adds a target→vuln relationship to the graph
func RecordTargetVuln(target, vulnType, severity, url, tool string) {
g := LoadGraph()

targetID := "target:" + target
vulnID := fmt.Sprintf("vuln:%s:%s", target, vulnType)
toolID := "tool:" + tool

g.AddNode(targetID, NodeTarget, target, map[string]string{"domain": target})
g.AddNode(vulnID, NodeVuln, vulnType, map[string]string{
"severity": severity,
"url":      url,
"target":   target,
})
g.AddNode(toolID, NodeTool, tool, nil)

// target has_vuln vuln
weight := severityToWeight(severity)
g.AddEdge(targetID, vulnID, EdgeHasVuln, weight, map[string]string{"url": url})

// vuln exploited_by tool
g.AddEdge(vulnID, toolID, EdgeExploitedBy, 1.0, nil)

SaveGraph(g)
}

// RecordTargetTech adds a target→tech relationship
func RecordTargetTech(target string, techStack []string) {
g := LoadGraph()
targetID := "target:" + target
g.AddNode(targetID, NodeTarget, target, nil)

for _, tech := range techStack {
if tech == "" {
continue
}
techID := "tech:" + strings.ToLower(tech)
g.AddNode(techID, NodeTech, tech, nil)
g.AddEdge(targetID, techID, EdgeUsesTech, 1.0, nil)
}
SaveGraph(g)
}

// RecordVulnChain records that vuln A leads to vuln B (exploit chain)
func RecordVulnChain(target, vulnA, vulnB, impact string) {
g := LoadGraph()
aID := fmt.Sprintf("vuln:%s:%s", target, vulnA)
bID := fmt.Sprintf("vuln:%s:%s", target, vulnB)
g.AddNode(aID, NodeVuln, vulnA, nil)
g.AddNode(bID, NodeVuln, vulnB, map[string]string{"chain_impact": impact})
g.AddEdge(aID, bID, EdgeLeadsTo, 0.9, map[string]string{"impact": impact})
SaveGraph(g)
}

// RecordWAFBypass records which payload bypassed a WAF
func RecordWAFBypass(target, wafVendor, payload, technique string) {
g := LoadGraph()
wafID := "tech:waf:" + strings.ToLower(wafVendor)
payloadID := fmt.Sprintf("payload:%s:%s", wafVendor, technique)
g.AddNode(wafID, NodeTech, "WAF:"+wafVendor, nil)
g.AddNode(payloadID, NodePayload, technique, map[string]string{
"payload":   payload,
"waf":       wafVendor,
"technique": technique,
})
g.AddEdge(wafID, payloadID, EdgeBypassedWith, 1.0, map[string]string{"target": target})
SaveGraph(g)
}

// GetRelatedVulns returns vulns found on targets with similar tech stack
func GetRelatedVulns(target string, techStack []string) []string {
g := LoadGraph()
techSet := make(map[string]bool)
for _, t := range techStack {
techSet["tech:"+strings.ToLower(t)] = true
}

// Find targets using same tech
relatedTargets := make(map[string]bool)
for _, edge := range g.Edges {
if edge.Type == EdgeUsesTech && techSet[edge.To] {
relatedTargets[edge.From] = true
}
}

// Find vulns on those targets
vulnSet := make(map[string]bool)
var vulns []string
for _, edge := range g.Edges {
if edge.Type == EdgeHasVuln && relatedTargets[edge.From] {
if node, ok := g.Nodes[edge.To]; ok {
key := node.Label
if !vulnSet[key] {
vulnSet[key] = true
vulns = append(vulns, key)
}
}
}
}
return vulns
}

// GetBestWAFBypass returns the best known bypass for a WAF vendor
func GetBestWAFBypass(wafVendor string) string {
g := LoadGraph()
wafID := "tech:waf:" + strings.ToLower(wafVendor)

for _, edge := range g.Edges {
if edge.Type == EdgeBypassedWith && edge.From == wafID {
if node, ok := g.Nodes[edge.To]; ok {
if payload, ok := node.Properties["payload"]; ok {
return payload
}
}
}
}
return ""
}

// GetGraphSummary returns a human-readable summary of the knowledge graph
func GetGlobalGraphSummary() string {
g := LoadGraph()
targets := 0
vulns := 0
techs := 0
for _, n := range g.Nodes {
switch n.Type {
case NodeTarget:
targets++
case NodeVuln:
vulns++
case NodeTech:
techs++
}
}
return fmt.Sprintf("Knowledge Graph: %d targets | %d vulns | %d tech nodes | %d relationships",
targets, vulns, techs, len(g.Edges))
}

// GetAttackPathSuggestions uses the graph to suggest attack paths for a target
func GetAttackPathSuggestions(target string, techStack []string) []string {
relatedVulns := GetRelatedVulns(target, techStack)
if len(relatedVulns) == 0 {
return nil
}

var suggestions []string
for _, v := range relatedVulns {
suggestions = append(suggestions, fmt.Sprintf("Similar targets had %s — prioritize this vector", v))
if len(suggestions) >= 5 {
break
}
}
return suggestions
}

func severityToWeight(severity string) float64 {
switch strings.ToLower(severity) {
case "critical":
return 1.0
case "high":
return 0.8
case "medium":
return 0.6
case "low":
return 0.4
default:
return 0.2
}
}

