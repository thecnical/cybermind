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
}

// isAvailable checks if a tool is installed
func isAvailable(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// run executes a command and returns output
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	// 60 second timeout per tool
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			combined := out.String() + errOut.String()
			if combined != "" {
				return combined, nil // return partial output even on error
			}
			return "", err
		}
		return out.String(), nil
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		return out.String(), fmt.Errorf("timeout after 60s")
	}
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
	usedTools := []string{}

	// 1. WHOIS
	progress("Running whois...")
	if isAvailable("whois") {
		start := time.Now()
		out, err := run("whois", target)
		tr := ToolResult{Tool: "whois", Command: "whois " + target, Took: time.Since(start)}
		if err == nil && out != "" {
			tr.Output = out
			usedTools = append(usedTools, "whois")
			allOutput.WriteString("=== WHOIS ===\n" + out + "\n\n")
		} else {
			tr.Error = "failed or no output"
		}
		result.Results = append(result.Results, tr)
	}

	// 2. DIG — DNS records
	progress("Running dig (DNS)...")
	if isAvailable("dig") {
		start := time.Now()
		out, err := run("dig", "+short", "ANY", target)
		if out == "" {
			out, err = run("dig", "+short", target)
		}
		tr := ToolResult{Tool: "dig", Command: "dig +short ANY " + target, Took: time.Since(start)}
		if err == nil && out != "" {
			tr.Output = out
			usedTools = append(usedTools, "dig")
			allOutput.WriteString("=== DNS (dig) ===\n" + out + "\n\n")
		} else {
			tr.Error = "failed or no output"
		}
		result.Results = append(result.Results, tr)
	}

	// 3. NMAP — port scan
	progress("Running nmap (port scan)...")
	if isAvailable("nmap") {
		start := time.Now()
		// Fast scan: top 1000 ports, service detection, no ping
		out, err := run("nmap", "-sV", "-T4", "--open", "-Pn", target)
		tr := ToolResult{Tool: "nmap", Command: "nmap -sV -T4 --open -Pn " + target, Took: time.Since(start)}
		if err == nil && out != "" {
			tr.Output = out
			usedTools = append(usedTools, "nmap")
			allOutput.WriteString("=== NMAP ===\n" + out + "\n\n")
		} else {
			tr.Error = "failed or no output"
		}
		result.Results = append(result.Results, tr)
	}

	// 4. SUBFINDER — subdomain enum (only for domains, not IPs)
	if !isIP(target) {
		progress("Running subfinder (subdomains)...")
		if isAvailable("subfinder") {
			start := time.Now()
			out, err := run("subfinder", "-d", target, "-silent")
			tr := ToolResult{Tool: "subfinder", Command: "subfinder -d " + target + " -silent", Took: time.Since(start)}
			if err == nil && out != "" {
				tr.Output = out
				usedTools = append(usedTools, "subfinder")
				allOutput.WriteString("=== SUBDOMAINS (subfinder) ===\n" + out + "\n\n")
			} else {
				tr.Error = "failed or no output"
			}
			result.Results = append(result.Results, tr)
		}

		// 5. HTTPX — check live hosts
		progress("Running httpx (live hosts)...")
		if isAvailable("httpx") {
			start := time.Now()
			out, err := run("httpx", "-u", target, "-silent", "-status-code", "-title", "-tech-detect")
			tr := ToolResult{Tool: "httpx", Command: "httpx -u " + target + " -silent -status-code -title -tech-detect", Took: time.Since(start)}
			if err == nil && out != "" {
				tr.Output = out
				usedTools = append(usedTools, "httpx")
				allOutput.WriteString("=== HTTP PROBE (httpx) ===\n" + out + "\n\n")
			} else {
				tr.Error = "failed or no output"
			}
			result.Results = append(result.Results, tr)
		}

		// 6. WHATWEB — tech fingerprint
		progress("Running whatweb (fingerprint)...")
		if isAvailable("whatweb") {
			start := time.Now()
			out, err := run("whatweb", "--color=never", target)
			tr := ToolResult{Tool: "whatweb", Command: "whatweb " + target, Took: time.Since(start)}
			if err == nil && out != "" {
				tr.Output = out
				usedTools = append(usedTools, "whatweb")
				allOutput.WriteString("=== TECH FINGERPRINT (whatweb) ===\n" + out + "\n\n")
			} else {
				tr.Error = "failed or no output"
			}
			result.Results = append(result.Results, tr)
		}
	}

	result.Tools = usedTools
	// Store combined output in first result for easy access
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
	tools := []string{"nmap", "subfinder", "httpx", "whatweb", "dig", "whois", "nuclei", "gobuster", "ffuf", "amass"}
	result := make(map[string]bool)
	for _, t := range tools {
		result[t] = isAvailable(t)
	}
	return result
}
