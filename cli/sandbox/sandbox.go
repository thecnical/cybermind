// Package sandbox — Vercel Sandbox integration for CyberMind
//
// Uses Vercel's browser sandbox to:
// 1. Verify XSS in a real browser (not just curl)
// 2. Perform authenticated scanning (login + capture session)
// 3. Take screenshots as bug evidence
// 4. Execute DOM-based XSS that curl can't detect
//
// Vercel Sandbox API: https://vercel.com/docs/sandbox
// The sandbox runs a headless Chromium browser on Vercel's infrastructure.
package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SandboxResult holds the result of a sandbox operation
type SandboxResult struct {
	Success    bool
	Output     string
	Screenshot string // base64 PNG
	Cookies    map[string]string
	Error      string
	Duration   time.Duration
}

// LoginResult holds captured session after authenticated login
type LoginResult struct {
	Success bool
	Cookies map[string]string
	Headers map[string]string
	Token   string // JWT or session token if found
	Error   string
}

// sandboxClient with reasonable timeout
var sandboxClient = &http.Client{Timeout: 60 * time.Second}

// getVercelToken returns the Vercel API token from env
func getVercelToken() string {
	return os.Getenv("VERCEL_TOKEN")
}

// isAvailable returns true if Vercel Sandbox is configured
func IsAvailable() bool {
	return getVercelToken() != ""
}

// ─── XSS Verification ────────────────────────────────────────────────────────

// VerifyXSSInBrowser uses Vercel Sandbox to verify XSS in a real browser.
// This catches DOM-based XSS that curl/dalfox miss.
func VerifyXSSInBrowser(targetURL, payload string) SandboxResult {
	start := time.Now()

	if !IsAvailable() {
		return SandboxResult{Error: "VERCEL_TOKEN not set — sandbox unavailable"}
	}

	// Build the sandbox script
	script := fmt.Sprintf(`
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  let xssTriggered = false;
  let xssPayload = '';
  
  // Listen for dialog (alert/confirm/prompt) — XSS indicator
  page.on('dialog', async dialog => {
    xssTriggered = true;
    xssPayload = dialog.message();
    await dialog.dismiss();
  });
  
  // Also listen for console errors that might indicate XSS
  page.on('console', msg => {
    if (msg.text().includes('cybermind_xss')) {
      xssTriggered = true;
    }
  });
  
  try {
    await page.goto('%s', { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(2000);
    
    const screenshot = await page.screenshot({ encoding: 'base64' });
    const title = await page.title();
    const url = page.url();
    
    console.log(JSON.stringify({
      xss_triggered: xssTriggered,
      xss_payload: xssPayload,
      title: title,
      final_url: url,
      screenshot: screenshot
    }));
  } catch (e) {
    console.log(JSON.stringify({ error: e.message }));
  }
  
  await browser.close();
})();
`, targetURL)

	result := runSandboxScript(script)
	result.Duration = time.Since(start)

	// Parse XSS result from output
	if strings.Contains(result.Output, `"xss_triggered":true`) {
		result.Success = true
	}

	return result
}

// ─── Authenticated Scanning ───────────────────────────────────────────────────

// LoginAndCapture performs a login flow in the sandbox and captures session cookies.
// Returns cookies/tokens that can be used for authenticated scanning.
func LoginAndCapture(loginURL, username, password string) LoginResult {
	if !IsAvailable() {
		return LoginResult{Error: "VERCEL_TOKEN not set — sandbox unavailable"}
	}

	script := fmt.Sprintf(`
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  
  const capturedTokens = [];
  
  // Intercept requests to capture auth tokens
  page.on('request', request => {
    const headers = request.headers();
    if (headers['authorization']) {
      capturedTokens.push(headers['authorization']);
    }
  });
  
  try {
    await page.goto('%s', { waitUntil: 'networkidle', timeout: 15000 });
    
    // Try common login form selectors
    const emailSelectors = ['input[type="email"]', 'input[name="email"]', 'input[name="username"]', '#email', '#username', '#user'];
    const passSelectors = ['input[type="password"]', 'input[name="password"]', '#password', '#pass'];
    const submitSelectors = ['button[type="submit"]', 'input[type="submit"]', 'button:has-text("Login")', 'button:has-text("Sign in")', 'button:has-text("Log in")'];
    
    let filled = false;
    for (const sel of emailSelectors) {
      try {
        await page.fill(sel, '%s', { timeout: 2000 });
        filled = true;
        break;
      } catch {}
    }
    
    for (const sel of passSelectors) {
      try {
        await page.fill(sel, '%s', { timeout: 2000 });
        break;
      } catch {}
    }
    
    if (filled) {
      for (const sel of submitSelectors) {
        try {
          await page.click(sel, { timeout: 2000 });
          break;
        } catch {}
      }
      await page.waitForTimeout(3000);
    }
    
    // Capture all cookies after login
    const cookies = await context.cookies();
    const cookieMap = {};
    cookies.forEach(c => { cookieMap[c.name] = c.value; });
    
    // Check localStorage for tokens
    const localStorageData = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
      }
      return data;
    });
    
    const finalURL = page.url();
    const loginSuccess = finalURL !== '%s'; // URL changed = likely logged in
    
    console.log(JSON.stringify({
      success: loginSuccess,
      cookies: cookieMap,
      tokens: capturedTokens,
      local_storage: localStorageData,
      final_url: finalURL
    }));
  } catch (e) {
    console.log(JSON.stringify({ error: e.message, success: false }));
  }
  
  await browser.close();
})();
`, loginURL, username, password, loginURL)

	result := runSandboxScript(script)

	var parsed struct {
		Success      bool              `json:"success"`
		Cookies      map[string]string `json:"cookies"`
		Tokens       []string          `json:"tokens"`
		LocalStorage map[string]string `json:"local_storage"`
		FinalURL     string            `json:"final_url"`
		Error        string            `json:"error"`
	}

	if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
		return LoginResult{Error: "parse error: " + err.Error()}
	}

	loginResult := LoginResult{
		Success: parsed.Success,
		Cookies: parsed.Cookies,
		Headers: make(map[string]string),
	}

	// Extract JWT token if found
	for _, t := range parsed.Tokens {
		if strings.HasPrefix(t, "Bearer ") {
			loginResult.Token = strings.TrimPrefix(t, "Bearer ")
			loginResult.Headers["Authorization"] = t
			break
		}
	}

	// Check localStorage for tokens
	for k, v := range parsed.LocalStorage {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "jwt") || strings.Contains(lower, "auth") {
			loginResult.Token = v
			loginResult.Headers["Authorization"] = "Bearer " + v
			break
		}
	}

	if parsed.Error != "" {
		loginResult.Error = parsed.Error
	}

	return loginResult
}

// ─── Screenshot Evidence ──────────────────────────────────────────────────────

// TakeScreenshot captures a screenshot of a URL as bug evidence.
func TakeScreenshot(targetURL string) (string, error) {
	if !IsAvailable() {
		return "", fmt.Errorf("VERCEL_TOKEN not set")
	}

	script := fmt.Sprintf(`
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1280, height: 720 });
  try {
    await page.goto('%s', { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(1000);
    const screenshot = await page.screenshot({ encoding: 'base64', fullPage: false });
    console.log(JSON.stringify({ screenshot }));
  } catch (e) {
    console.log(JSON.stringify({ error: e.message }));
  }
  await browser.close();
})();
`, targetURL)

	result := runSandboxScript(script)
	if result.Error != "" {
		return "", fmt.Errorf(result.Error)
	}

	var parsed struct {
		Screenshot string `json:"screenshot"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
		return "", err
	}
	return parsed.Screenshot, nil
}

// ─── Sandbox Runner ───────────────────────────────────────────────────────────

// runSandboxScript executes a Node.js script in Vercel Sandbox
func runSandboxScript(script string) SandboxResult {
	token := getVercelToken()
	if token == "" {
		return SandboxResult{Error: "VERCEL_TOKEN not configured"}
	}

	// Vercel Sandbox API
	payload := map[string]interface{}{
		"runtime": "nodejs",
		"code":    script,
		"packages": []string{"playwright"},
		"timeout": 30,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return SandboxResult{Error: err.Error()}
	}

	req, err := http.NewRequest("POST", "https://api.vercel.com/v1/sandbox/run", bytes.NewBuffer(body))
	if err != nil {
		return SandboxResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := sandboxClient.Do(req)
	if err != nil {
		return SandboxResult{Error: "sandbox request failed: " + err.Error()}
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	var result struct {
		Output string `json:"output"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return SandboxResult{Error: "parse error: " + string(raw[:min(200, len(raw))])}
	}

	output := result.Output
	if output == "" {
		output = result.Stdout
	}

	return SandboxResult{
		Success: result.Error == "",
		Output:  output,
		Error:   result.Error,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
