// Package mcp implements a Model Context Protocol server for CyberMind.
// Any MCP-compatible AI (Claude, GPT-4, Gemini) can orchestrate CyberMind tools natively.
// Supports stdio and HTTP transports.
//
// Usage:
//   cybermind --mcp-server          → stdio transport (for Claude Desktop, etc.)
//   cybermind --mcp-server --http   → HTTP transport on :8765
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ─── JSON-RPC 2.0 types ───────────────────────────────────────────────────────

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Notification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// ─── MCP Protocol types ───────────────────────────────────────────────────────

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe"`
	ListChanged bool `json:"listChanged"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Enum        []string `json:"enum,omitempty"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

var cybermindTools = []Tool{
	{
		Name:        "nmap_scan",
		Description: "Run nmap port scan against a target. Returns open ports, services, and OS detection.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target": {Type: "string", Description: "Target IP, hostname, or CIDR range (e.g. example.com, 192.168.1.0/24)"},
				"flags":  {Type: "string", Description: "Additional nmap flags (e.g. -sV -O --script vuln). Default: -sV -T4 --top-ports 1000"},
			},
			Required: []string{"target"},
		},
	},
	{
		Name:        "subfinder_enum",
		Description: "Enumerate subdomains of a domain using subfinder. Returns list of discovered subdomains.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"domain": {Type: "string", Description: "Target domain (e.g. example.com)"},
				"silent": {Type: "string", Description: "Run silently (true/false). Default: true"},
			},
			Required: []string{"domain"},
		},
	},
	{
		Name:        "nuclei_scan",
		Description: "Run nuclei vulnerability scanner with templates. Returns CVEs, misconfigs, and security issues.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target":   {Type: "string", Description: "Target URL or domain"},
				"severity": {Type: "string", Description: "Severity filter: critical,high,medium,low,info. Default: critical,high,medium"},
				"tags":     {Type: "string", Description: "Template tags to run (e.g. cve,xss,sqli,ssrf). Default: all"},
			},
			Required: []string{"target"},
		},
	},
	{
		Name:        "dalfox_xss",
		Description: "Run dalfox XSS scanner against a URL. Returns confirmed XSS vulnerabilities with PoC.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":         {Type: "string", Description: "Target URL with parameters (e.g. https://example.com/search?q=test)"},
				"waf_bypass":  {Type: "string", Description: "Enable WAF bypass mode (true/false). Default: false"},
				"cookie":      {Type: "string", Description: "Session cookie for authenticated scanning (e.g. session=abc123)"},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "sqlmap_sqli",
		Description: "Run sqlmap SQL injection scanner. Returns injectable parameters and database info.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":    {Type: "string", Description: "Target URL (e.g. https://example.com/page?id=1)"},
				"level":  {Type: "string", Description: "Test level 1-5. Default: 3"},
				"risk":   {Type: "string", Description: "Risk level 1-3. Default: 2"},
				"cookie": {Type: "string", Description: "Session cookie for authenticated scanning"},
				"dbs":    {Type: "string", Description: "Enumerate databases (true/false). Default: false"},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "httpx_probe",
		Description: "Probe HTTP/HTTPS services with httpx. Returns status codes, titles, tech stack, and response info.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"targets": {Type: "string", Description: "Comma-separated list of URLs or domains to probe"},
				"flags":   {Type: "string", Description: "Additional httpx flags (e.g. -title -tech-detect -status-code)"},
			},
			Required: []string{"targets"},
		},
	},
	{
		Name:        "katana_crawl",
		Description: "Crawl a web application with katana. Returns discovered URLs, endpoints, and JS files.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"url":   {Type: "string", Description: "Target URL to crawl"},
				"depth": {Type: "string", Description: "Crawl depth. Default: 3"},
				"jc":    {Type: "string", Description: "Enable JS crawling (true/false). Default: true"},
			},
			Required: []string{"url"},
		},
	},
	{
		Name:        "trufflehog_secrets",
		Description: "Scan for exposed secrets, API keys, and tokens using trufflehog.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target": {Type: "string", Description: "Target URL, git repo URL, or filesystem path to scan"},
				"json":   {Type: "string", Description: "Output as JSON (true/false). Default: true"},
			},
			Required: []string{"target"},
		},
	},
	{
		Name:        "cybermind_recon",
		Description: "Run CyberMind full recon pipeline (30+ tools: subfinder, nmap, httpx, nuclei, katana, etc.). Returns comprehensive attack surface map.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target": {Type: "string", Description: "Target domain or IP"},
				"mode":   {Type: "string", Description: "Scan mode: quick, deep, overnight. Default: deep", Enum: []string{"quick", "deep", "overnight"}},
				"focus":  {Type: "string", Description: "Vulnerability focus: xss,sqli,ssrf,idor,rce or all. Default: all"},
				"cookie": {Type: "string", Description: "Session cookie for authenticated scanning"},
			},
			Required: []string{"target"},
		},
	},
	{
		Name:        "cybermind_hunt",
		Description: "Run CyberMind vulnerability hunt pipeline (40+ tools: dalfox, sqlmap, nuclei, paramspider, etc.). Returns confirmed vulnerabilities.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"target": {Type: "string", Description: "Target domain or URL"},
				"focus":  {Type: "string", Description: "Vulnerability type: xss,sqli,ssrf,idor,rce,all. Default: all"},
				"cookie": {Type: "string", Description: "Session cookie for authenticated scanning"},
				"bearer": {Type: "string", Description: "Bearer token for API authentication"},
			},
			Required: []string{"target"},
		},
	},
}

// ─── Tool execution ───────────────────────────────────────────────────────────

func executeTool(name string, args map[string]interface{}) ToolResult {
	getString := func(key, def string) string {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return def
	}

	getBool := func(key string) bool {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s == "true" || s == "1" || s == "yes"
			}
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}

	runCmd := func(name string, cmdArgs ...string) string {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Sprintf("Tool '%s' not installed. Run: cybermind /doctor", name)
		}
		cmd := exec.Command(name, cmdArgs...)
		cmd.Stdin = nil
		out, err := cmd.CombinedOutput()
		result := strings.TrimSpace(string(out))
		if result == "" && err != nil {
			return fmt.Sprintf("Error: %v", err)
		}
		if len(result) > 50000 {
			result = result[:50000] + "\n...[truncated]"
		}
		return result
	}

	var output string

	switch name {
	case "nmap_scan":
		target := getString("target", "")
		if target == "" {
			return errorResult("target is required")
		}
		flags := getString("flags", "-sV -T4 --top-ports 1000")
		flagParts := strings.Fields(flags)
		cmdArgs := append(flagParts, target)
		output = runCmd("nmap", cmdArgs...)

	case "subfinder_enum":
		domain := getString("domain", "")
		if domain == "" {
			return errorResult("domain is required")
		}
		silent := getString("silent", "true")
		cmdArgs := []string{"-d", domain}
		if silent == "true" {
			cmdArgs = append(cmdArgs, "-silent")
		}
		output = runCmd("subfinder", cmdArgs...)

	case "nuclei_scan":
		target := getString("target", "")
		if target == "" {
			return errorResult("target is required")
		}
		severity := getString("severity", "critical,high,medium")
		tags := getString("tags", "")
		cmdArgs := []string{"-u", target, "-severity", severity, "-silent", "-no-color"}
		if tags != "" {
			cmdArgs = append(cmdArgs, "-tags", tags)
		}
		output = runCmd("nuclei", cmdArgs...)

	case "dalfox_xss":
		url := getString("url", "")
		if url == "" {
			return errorResult("url is required")
		}
		cmdArgs := []string{"url", url, "--silence", "--no-color"}
		if getBool("waf_bypass") {
			cmdArgs = append(cmdArgs, "--waf-bypass")
		}
		if cookie := getString("cookie", ""); cookie != "" {
			cmdArgs = append(cmdArgs, "--cookie", cookie)
		}
		output = runCmd("dalfox", cmdArgs...)

	case "sqlmap_sqli":
		url := getString("url", "")
		if url == "" {
			return errorResult("url is required")
		}
		level := getString("level", "3")
		risk := getString("risk", "2")
		cmdArgs := []string{"-u", url, "--level=" + level, "--risk=" + risk, "--batch", "--random-agent"}
		if cookie := getString("cookie", ""); cookie != "" {
			cmdArgs = append(cmdArgs, "--cookie", cookie)
		}
		if getBool("dbs") {
			cmdArgs = append(cmdArgs, "--dbs")
		}
		output = runCmd("sqlmap", cmdArgs...)

	case "httpx_probe":
		targets := getString("targets", "")
		if targets == "" {
			return errorResult("targets is required")
		}
		flags := getString("flags", "-title -tech-detect -status-code -silent")
		flagParts := strings.Fields(flags)
		// Write targets to temp file
		f, err := os.CreateTemp("", "cybermind-mcp-*.txt")
		if err != nil {
			return errorResult("failed to create temp file: " + err.Error())
		}
		defer os.Remove(f.Name())
		for _, t := range strings.Split(targets, ",") {
			f.WriteString(strings.TrimSpace(t) + "\n")
		}
		f.Close()
		cmdArgs := append([]string{"-l", f.Name()}, flagParts...)
		output = runCmd("httpx", cmdArgs...)

	case "katana_crawl":
		url := getString("url", "")
		if url == "" {
			return errorResult("url is required")
		}
		depth := getString("depth", "3")
		cmdArgs := []string{"-u", url, "-d", depth, "-silent", "-no-color"}
		if getString("jc", "true") == "true" {
			cmdArgs = append(cmdArgs, "-jc")
		}
		output = runCmd("katana", cmdArgs...)

	case "trufflehog_secrets":
		target := getString("target", "")
		if target == "" {
			return errorResult("target is required")
		}
		cmdArgs := []string{"--no-update"}
		if getString("json", "true") == "true" {
			cmdArgs = append(cmdArgs, "--json")
		}
		if strings.HasPrefix(target, "http") {
			cmdArgs = append([]string{"git", target}, cmdArgs...)
		} else {
			cmdArgs = append([]string{"filesystem", target}, cmdArgs...)
		}
		output = runCmd("trufflehog", cmdArgs...)

	case "cybermind_recon":
		target := getString("target", "")
		if target == "" {
			return errorResult("target is required")
		}
		mode := getString("mode", "deep")
		focus := getString("focus", "all")
		cookie := getString("cookie", "")
		// Run cybermind /recon via subprocess
		cmdArgs := []string{"/recon", target}
		if cookie != "" {
			os.Setenv("CYBERMIND_MCP_COOKIE", cookie)
		}
		if focus != "all" {
			os.Setenv("CYBERMIND_FOCUS_BUGS", focus)
		}
		os.Setenv("CYBERMIND_EXEC_MODE", mode)
		exe, _ := os.Executable()
		cmd := exec.Command(exe, cmdArgs...)
		cmd.Stdin = nil
		out, _ := cmd.CombinedOutput()
		output = strings.TrimSpace(string(out))
		if len(output) > 50000 {
			output = output[:50000] + "\n...[truncated]"
		}

	case "cybermind_hunt":
		target := getString("target", "")
		if target == "" {
			return errorResult("target is required")
		}
		focus := getString("focus", "all")
		cookie := getString("cookie", "")
		bearer := getString("bearer", "")
		if cookie != "" {
			os.Setenv("CYBERMIND_MCP_COOKIE", cookie)
		}
		if bearer != "" {
			os.Setenv("CYBERMIND_MCP_BEARER", bearer)
		}
		if focus != "all" {
			os.Setenv("CYBERMIND_FOCUS_BUGS", focus)
		}
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "/hunt", target)
		cmd.Stdin = nil
		out, _ := cmd.CombinedOutput()
		output = strings.TrimSpace(string(out))
		if len(output) > 50000 {
			output = output[:50000] + "\n...[truncated]"
		}

	default:
		return errorResult(fmt.Sprintf("unknown tool: %s", name))
	}

	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: output}},
	}
}

func errorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: "Error: " + msg}},
		IsError: true,
	}
}

// ─── Request handler ──────────────────────────────────────────────────────────

func handleRequest(req Request) Response {
	resp := Response{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": ServerInfo{
				Name:    "cybermind",
				Version: "5.5.1",
			},
			"capabilities": Capabilities{
				Tools: &ToolsCapability{ListChanged: false},
			},
		}

	case "tools/list":
		resp.Result = map[string]interface{}{
			"tools": cybermindTools,
		}

	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &RPCError{Code: -32602, Message: "invalid params: " + err.Error()}
			return resp
		}
		result := executeTool(params.Name, params.Arguments)
		resp.Result = result

	case "ping":
		resp.Result = map[string]interface{}{}

	default:
		resp.Error = &RPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}
	}

	return resp
}

// ─── Stdio transport ──────────────────────────────────────────────────────────

// RunStdio runs the MCP server on stdio (for Claude Desktop, Cursor, etc.)
// Reads JSON-RPC requests from stdin, writes responses to stdout.
func RunStdio() {
	fmt.Fprintln(os.Stderr, "[CyberMind MCP] stdio transport started")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 10*1024*1024), 10*1024*1024) // 10MB buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errResp := Response{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
			}
			data, _ := json.Marshal(errResp)
			fmt.Println(string(data))
			continue
		}

		resp := handleRequest(req)
		data, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		fmt.Println(string(data))
	}
}

// ─── HTTP transport ───────────────────────────────────────────────────────────

// RunHTTP runs the MCP server on HTTP (for remote MCP clients).
// POST /mcp/invoke — single tool invocation
// POST /mcp/rpc    — JSON-RPC 2.0 endpoint
func RunHTTP(addr string) error {
	mux := http.NewServeMux()

	// JSON-RPC endpoint
	mux.HandleFunc("/mcp/rpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			resp := Response{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "parse error"},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		resp := handleRequest(req)
		json.NewEncoder(w).Encode(resp)
	})

	// Simple tool invocation endpoint
	mux.HandleFunc("/mcp/invoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		var params CallToolParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		result := executeTool(params.Name, params.Arguments)
		json.NewEncoder(w).Encode(result)
	})

	// Tools list
	mux.HandleFunc("/mcp/tools", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]interface{}{"tools": cybermindTools})
	})

	// Health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"server":  "cybermind-mcp",
			"version": "5.5.1",
			"tools":   len(cybermindTools),
			"time":    time.Now().Unix(),
		})
	})

	fmt.Fprintf(os.Stderr, "[CyberMind MCP] HTTP server listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "[CyberMind MCP] Endpoints:\n")
	fmt.Fprintf(os.Stderr, "  POST %s/mcp/rpc     — JSON-RPC 2.0\n", addr)
	fmt.Fprintf(os.Stderr, "  POST %s/mcp/invoke  — simple tool call\n", addr)
	fmt.Fprintf(os.Stderr, "  GET  %s/mcp/tools   — list tools\n", addr)

	return http.ListenAndServe(addr, mux)
}

// PrintMCPConfig prints the mcp.json config snippet for Claude Desktop / Cursor.
func PrintMCPConfig() {
	exe, _ := os.Executable()
	config := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"cybermind": map[string]interface{}{
				"command": exe,
				"args":    []string{"--mcp-server"},
				"env":     map[string]string{},
			},
		},
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	fmt.Println("\nAdd this to your Claude Desktop / Cursor mcp.json:")
	fmt.Println(string(data))
	fmt.Println("\nOr run HTTP server: cybermind --mcp-server --http :8765")
}
