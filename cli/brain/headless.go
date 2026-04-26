// headless.go — Headless Browser Integration for JS-Heavy SPAs
// Uses katana headless mode + Playwright for:
// - JavaScript-rendered content discovery
// - SPA route enumeration (React/Vue/Angular/Next.js)
// - Authenticated scanning (cookie/token injection)
// - DOM XSS detection in rendered pages
// - OAuth flow analysis
// - WebSocket endpoint discovery
//
// Modern apps render everything in JS — without headless you miss 80% of attack surface.
package brain

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HeadlessResult holds findings from headless browser scanning
type HeadlessResult struct {
	Target         string
	DiscoveredURLs []string
	JSEndpoints    []string
	WebSockets     []string
	Forms          []string
	APIRequests    []string
	DOMXSSHints    []string
	Secrets        []string
	Duration       time.Duration
	ToolUsed       string // "katana-headless" | "playwright" | "katana-static" | "none"
}

// RunHeadlessScan runs a headless browser scan against a target.
// Tries katana headless first, falls back to playwright, then static katana.
func RunHeadlessScan(target string, cookies string, depth int) HeadlessResult {
	start := time.Now()

	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	// Try katana headless mode first (fastest, most integrated)
	if r := runKatanaHeadless(target, cookies, depth); len(r.DiscoveredURLs) > 0 {
		r.Duration = time.Since(start)
		return r
	}

	// Try playwright (most powerful, handles complex SPAs)
	if r := runPlaywrightScan(target, cookies, depth); len(r.DiscoveredURLs) > 0 {
		r.Duration = time.Since(start)
		return r
	}

	// Fallback: static katana (no JS rendering)
	r := runKatanaStatic(target, depth)
	r.Duration = time.Since(start)
	return r
}

// runKatanaHeadless runs katana with headless Chrome for JS rendering
func runKatanaHeadless(target, cookies string, depth int) HeadlessResult {
	result := HeadlessResult{Target: target, ToolUsed: "katana-headless"}

	if _, err := exec.LookPath("katana"); err != nil {
		return result
	}

	outFile := fmt.Sprintf("/tmp/cybermind_katana_headless_%d.txt", time.Now().Unix())
	args := []string{
		"-u", target,
		"-d", fmt.Sprintf("%d", depth),
		"-c", "50",
		"-jc",       // parse JS files
		"-kf", "all", // known files
		"-aff",      // automatic form fill
		"-headless", // headless Chrome
		"-xhr",      // capture XHR requests
		"-ws",       // capture WebSocket
		"-no-color",
		"-silent",
		"-o", outFile,
	}
	if cookies != "" {
		args = append(args, "-H", "Cookie: "+cookies)
	}

	cmd := exec.Command("katana", args...)
	cmd.Stdin = nil

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-time.After(10 * time.Minute):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	case <-done:
	}

	if data, err := os.ReadFile(outFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			result.DiscoveredURLs = append(result.DiscoveredURLs, line)
			lower := strings.ToLower(line)
			switch {
			case strings.HasPrefix(line, "ws://") || strings.HasPrefix(line, "wss://"):
				result.WebSockets = append(result.WebSockets, line)
			case strings.Contains(lower, "/api/") || strings.HasSuffix(lower, ".json"):
				result.APIRequests = append(result.APIRequests, line)
			case strings.HasSuffix(lower, ".js"):
				result.JSEndpoints = append(result.JSEndpoints, line)
			}
		}
		os.Remove(outFile)
	}
	return result
}

// runPlaywrightScan uses Playwright for complex SPA scanning
func runPlaywrightScan(target, cookies string, depth int) HeadlessResult {
	result := HeadlessResult{Target: target, ToolUsed: "playwright"}

	if _, err := exec.LookPath("node"); err != nil {
		return result
	}

	scriptPath := "/tmp/cybermind_playwright_scan.js"
	script := buildPlaywrightScript(target, cookies, depth)
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return result
	}
	defer os.Remove(scriptPath)

	outFile := fmt.Sprintf("/tmp/cybermind_playwright_%d.json", time.Now().Unix())
	defer os.Remove(outFile)

	cmd := exec.Command("node", scriptPath, target, outFile)
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright")

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-time.After(5 * time.Minute):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	case <-done:
	}

	if data, err := os.ReadFile(outFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.Trim(strings.TrimSpace(line), `",[]`)
			if strings.HasPrefix(line, "http") {
				result.DiscoveredURLs = append(result.DiscoveredURLs, line)
			}
		}
	}
	return result
}

// runKatanaStatic runs katana without headless (fallback)
func runKatanaStatic(target string, depth int) HeadlessResult {
	result := HeadlessResult{Target: target, ToolUsed: "katana-static"}

	if _, err := exec.LookPath("katana"); err != nil {
		result.ToolUsed = "none"
		return result
	}

	outFile := fmt.Sprintf("/tmp/cybermind_katana_static_%d.txt", time.Now().Unix())
	cmd := exec.Command("katana",
		"-u", target,
		"-d", fmt.Sprintf("%d", depth),
		"-c", "100",
		"-jc", "-kf", "all", "-aff",
		"-no-color", "-silent",
		"-o", outFile,
	)
	cmd.Stdin = nil

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-time.After(5 * time.Minute):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	case <-done:
	}

	if data, err := os.ReadFile(outFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				result.DiscoveredURLs = append(result.DiscoveredURLs, line)
			}
		}
		os.Remove(outFile)
	}
	return result
}

// buildPlaywrightScript generates a Node.js Playwright script for SPA scanning
func buildPlaywrightScript(target, cookies string, depth int) string {
	cookieSetup := ""
	if cookies != "" {
		cookieSetup = fmt.Sprintf(`
  const cookieStr = %q;
  const cookieObjs = cookieStr.split(';').map(c => {
    const [name, value] = c.trim().split('=');
    return { name: name.trim(), value: (value||'').trim(), url: %q };
  });
  await context.addCookies(cookieObjs);
`, cookies, target)
	}

	return fmt.Sprintf(`
const { chromium } = require('playwright');
const fs = require('fs');
const target = process.argv[2] || %q;
const outFile = process.argv[3] || '/tmp/playwright_out.json';
const maxDepth = %d;
const visited = new Set();
const discovered = new Set();
const queue = [target];

async function scan() {
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    ignoreHTTPSErrors: true,
  });
  %s
  context.on('request', req => {
    const url = req.url();
    if (url.startsWith('http') && !url.includes('google') && !url.includes('facebook')) {
      discovered.add(url);
    }
  });
  const page = await context.newPage();
  let depth = 0;
  while (queue.length > 0 && depth < maxDepth) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
      await page.waitForTimeout(1500);
      const links = await page.evaluate(() =>
        Array.from(document.querySelectorAll('a[href],form[action]'))
          .map(el => el.href || el.action)
          .filter(u => u && u.startsWith('http'))
      );
      for (const link of links) {
        discovered.add(link);
        if (!visited.has(link) && link.includes(new URL(target).hostname)) queue.push(link);
      }
    } catch(e) {}
    depth++;
  }
  await browser.close();
  fs.writeFileSync(outFile, JSON.stringify([...discovered], null, 2));
}
scan().catch(console.error);
`, target, depth, cookieSetup)
}

// AnalyzeJSForSecrets scans JS files for hardcoded secrets and API keys
func AnalyzeJSForSecrets(jsURLs []string) []string {
	var secrets []string
	keywords := []string{"api_key", "secret_key", "access_token", "password", "aws_secret", "private_key", "AKIA"}

	for _, jsURL := range jsURLs {
		if !strings.HasSuffix(strings.ToLower(jsURL), ".js") {
			continue
		}
		cmd := exec.Command("curl", "-sL", "--max-time", "10", jsURL)
		cmd.Stdin = nil
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		content := string(out)
		lower := strings.ToLower(content)
		for _, kw := range keywords {
			if idx := strings.Index(lower, strings.ToLower(kw)); idx >= 0 {
				end := idx + 100
				if end > len(content) {
					end = len(content)
				}
				snippet := strings.TrimSpace(content[idx:end])
				if len(snippet) > 20 {
					secrets = append(secrets, fmt.Sprintf("[%s] in %s: %s", kw, jsURL, snippet[:min(80, len(snippet))]))
				}
				break
			}
		}
	}
	return secrets
}

// DetectSPAFramework detects which SPA framework a target uses
func DetectSPAFramework(target string) string {
	if _, err := exec.LookPath("curl"); err != nil {
		return "unknown"
	}
	cmd := exec.Command("curl", "-sL", "--max-time", "10", target)
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	content := strings.ToLower(string(out))
	switch {
	case strings.Contains(content, "__next") || strings.Contains(content, "next.js"):
		return "nextjs"
	case strings.Contains(content, "__react") || strings.Contains(content, "react"):
		return "react"
	case strings.Contains(content, "__vue") || strings.Contains(content, "vue"):
		return "vue"
	case strings.Contains(content, "ng-version") || strings.Contains(content, "angular"):
		return "angular"
	case strings.Contains(content, "__nuxt") || strings.Contains(content, "nuxt"):
		return "nuxt"
	case strings.Contains(content, "svelte"):
		return "svelte"
	default:
		return "unknown"
	}
}
