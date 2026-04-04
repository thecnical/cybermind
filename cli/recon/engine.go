package recon

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// ToolResult holds output from a single tool
type ToolResult struct {
	Tool    string
	Command string
	Output  string
	Error   string
	Took    time.Duration
}

// ReconResult holds all tool outputs
type ReconResult struct {
	Target  string
	Results []ToolResult
	Tools   []string
	Failed  []string
}

// isAvailable checks if a tool is installed
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// run executes a command with timeout, returns output
func run(timeoutSec int, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		combined := out.String()
		if combined == "" {
			combined = errOut.String()
		}
		if err != nil && combined == "" {
			return "", err
		}
		return combined, nil
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		partial := out.String()
		if partial != "" {
			return partial + "\n[timeout — partial results]", nil
		}
		return "", fmt.Errorf("timeout after %ds", timeoutSec)
	}
}

// sanitize removes ANSI codes and trims output to max length
func sanitize(s string, maxLen int) string {
	// Remove ANSI escape codes
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// Skip until 'm'
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		result.WriteByte(s[i])
		i++
	}
	clean := result.String()
	if len(clean) > maxLen {
		return clean[:maxLen] + "\n... [truncated]"
	}
	return clean
}

// isIP checks if target looks like an IP address
func isIP(target string) bool {
	parts := strings.Split(target, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
	}
	return true
}

// RunAutoRecon runs all available recon tools against target
func RunAutoRecon(target string, progress func(string)) ReconResult {
	result := ReconResult{Target: target}
	var allOutput strings.Builder

	addResult := func(tool, cmd, output, errMsg string, took time.Duration) {
		tr := ToolResult{Tool: tool, Command: cmd, Took: took}
		if output != "" && errMsg == "" {
			tr.Output = sanitize(output, 5000)
			result.Tools = append(result.Tools, tool)
			allOutput.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", strings.ToUpper(tool), tr.Output))
		} else {
			tr.Error = errMsg
			result.Failed = append(result.Failed, tool)
		}
		result.Results = append(result.Results, tr)
	}

	// 1. WHOIS
	if isAvailable("whois") {
		progress("whois — domain registration info...")
		start := time.Now()
		out, err := run(30, "whois", target)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		addResult("whois", "whois "+target, out, errMsg, time.Since(start))
	}

	// 2. DIG — DNS
	if isAvailable("dig") {
		progress("dig — DNS records...")
		start := time.Now()
		out, _ := run(15, "dig", "+short", "ANY", target)
		if out == "" {
			out, _ = run(15, "dig", "+short", target)
		}
		addResult("dig", "dig +short ANY "+target, out, "", time.Since(start))
	}

	// 3. NMAP — port scan
	if isAvailable("nmap") {
		progress("nmap — port scan + service detection (this may take a minute)...")
		start := time.Now()
		out, err := run(120, "nmap", "-sV", "-T4", "--open", "-Pn", "--top-ports", "1000", target)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		addResult("nmap", "nmap -sV -T4 --open -Pn --top-ports 1000 "+target, out, errMsg, time.Since(start))
	}

	// Domain-only tools
	if !isIP(target) {
		// 4. SUBFINDER
		if isAvailable("subfinder") {
			progress("subfinder — subdomain enumeration...")
			start := time.Now()
			out, err := run(60, "subfinder", "-d", target, "-silent")
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("subfinder", "subfinder -d "+target+" -silent", out, errMsg, time.Since(start))
		}

		// 5. AMASS (passive only — fast)
		if isAvailable("amass") {
			progress("amass — passive subdomain enum...")
			start := time.Now()
			out, err := run(60, "amass", "enum", "-passive", "-d", target)
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("amass", "amass enum -passive -d "+target, out, errMsg, time.Since(start))
		}

		// 6. HTTPX — live hosts
		if isAvailable("httpx") {
			progress("httpx — HTTP probe + tech detection...")
			start := time.Now()
			out, err := run(30, "httpx", "-u", target, "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects")
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("httpx", "httpx -u "+target+" -silent -status-code -title -tech-detect", out, errMsg, time.Since(start))
		}

		// 7. WHATWEB — fingerprint
		if isAvailable("whatweb") {
			progress("whatweb — technology fingerprint...")
			start := time.Now()
			out, err := run(30, "whatweb", "--color=never", "-a", "3", target)
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("whatweb", "whatweb --color=never -a 3 "+target, out, errMsg, time.Since(start))
		}

		// 8. GOBUSTER — directory bruteforce (fast wordlist)
		if isAvailable("gobuster") {
			progress("gobuster — directory bruteforce...")
			start := time.Now()
			// Use common wordlist if available
			wordlist := "/usr/share/wordlists/dirb/common.txt"
			if !isAvailable("ls") {
				wordlist = "/usr/share/wordlists/dirb/common.txt"
			}
			out, err := run(60, "gobuster", "dir", "-u", "http://"+target, "-w", wordlist, "-q", "--no-error", "-t", "20")
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("gobuster", "gobuster dir -u http://"+target+" -w "+wordlist+" -q -t 20", out, errMsg, time.Since(start))
		}

		// 9. NUCLEI — vulnerability scan (fast templates)
		if isAvailable("nuclei") {
			progress("nuclei — vulnerability scan...")
			start := time.Now()
			out, err := run(90, "nuclei", "-u", target, "-silent", "-severity", "critical,high,medium", "-no-color")
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			addResult("nuclei", "nuclei -u "+target+" -silent -severity critical,high,medium", out, errMsg, time.Since(start))
		}
	}

	// Store combined output
	if allOutput.Len() > 0 {
		result.Results = append([]ToolResult{{
			Tool:   "combined",
			Output: allOutput.String(),
		}}, result.Results...)
	}

	return result
}

// GetCombinedOutput returns all tool outputs as one string
func GetCombinedOutput(r ReconResult) string {
	for _, tr := range r.Results {
		if tr.Tool == "combined" {
			return tr.Output
		}
	}
	var b strings.Builder
	for _, tr := range r.Results {
		if tr.Output != "" {
			b.WriteString("=== " + strings.ToUpper(tr.Tool) + " ===\n")
			b.WriteString(tr.Output + "\n\n")
		}
	}
	return b.String()
}

// CheckTools returns which recon tools are available
func CheckTools() map[string]bool {
	tools := []string{
		"nmap", "masscan", "rustscan",
		"subfinder", "amass", "httpx", "whatweb",
		"dig", "whois", "nuclei",
		"gobuster", "ffuf", "feroxbuster",
		"nikto", "sqlmap", "burpsuite",
	}
	result := make(map[string]bool)
	for _, t := range tools {
		result[t] = isAvailable(t)
	}
	return result
}
