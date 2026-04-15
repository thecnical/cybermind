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
