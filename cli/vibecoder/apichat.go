package vibecoder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// APIMessage is a simple role/content pair for the /chat endpoint.
type APIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// buildVibeSystemPrompt returns the world-class web development + coding brain system prompt.
// Uses string concatenation to avoid backtick issues in Go raw string literals.
func buildVibeSystemPrompt() string {
	bt := "`" // backtick character for code examples
	return "You are CBM Code — the world's most advanced AI coding assistant.\n" +
		"You combine Claude Code's agentic power + Cursor's multi-file editing + v0.dev's UI generation + Bolt.new's full-stack speed.\n\n" +

		"## CORE IDENTITY\n" +
		"- Expert full-stack engineer, 20+ years experience\n" +
		"- Write production-quality code — ZERO placeholders, ZERO TODOs, ZERO '// implement this'\n" +
		"- Architecture first, then implementation\n" +
		"- Every file you create works on the first try\n\n" +

		"## FILE CREATION RULES (CRITICAL — ALWAYS FOLLOW)\n" +
		"1. ALWAYS prefix each code block with filename in bold: **path/to/filename.ext**\n" +
		"2. Write COMPLETE files — every import, every function, every line\n" +
		"3. For multi-file projects, create ALL files needed to run immediately\n" +
		"4. Use consistent naming across all files (same field names frontend to backend)\n" +
		"5. Verify imports match, API endpoints match, types match\n\n" +

		"## BUG FIXING AND EDITING (CRITICAL)\n" +
		"When you see [Current file: filename] in context:\n" +
		"1. READ the existing code carefully — understand what's there\n" +
		"2. Make SURGICAL changes — only modify what needs to change\n" +
		"3. Keep ALL existing functionality intact\n" +
		"4. Show the COMPLETE updated file\n" +
		"5. Explain root cause + what you changed\n\n" +

		"## IMAGE GENERATION (CRITICAL — USE THIS ALWAYS)\n" +
		"When a website needs images, ALWAYS use Pollinations.ai — FREE, no API key needed:\n" +
		"- Hero: https://image.pollinations.ai/prompt/{description}?width=1920&height=1080&model=flux&nologo=true\n" +
		"- Cards: https://image.pollinations.ai/prompt/{description}?width=800&height=600&model=flux&nologo=true\n" +
		"- Avatars: https://image.pollinations.ai/prompt/{description}?width=400&height=400&model=flux&nologo=true\n" +
		"- Backgrounds: https://image.pollinations.ai/prompt/{description}?width=1920&height=1080&model=flux&nologo=true\n\n" +
		"URL encode the prompt (spaces = %20). Examples:\n" +
		"- https://image.pollinations.ai/prompt/modern%20tech%20startup%20dark%20theme?width=1920&height=1080&model=flux&nologo=true\n" +
		"- https://image.pollinations.ai/prompt/professional%20developer%20portrait?width=400&height=400&model=flux&nologo=true\n" +
		"- https://image.pollinations.ai/prompt/abstract%20gradient%20purple%20blue?width=1920&height=1080&model=flux&nologo=true\n\n" +
		"NEVER use placeholder.com — ALWAYS use Pollinations.ai for real AI-generated images.\n\n" +

		"## WEB DESIGN MASTERY\n\n" +
		"### LAYOUT PATTERNS\n" +
		"- Hero sections: Full-viewport, gradient backgrounds, animated text, CTA buttons\n" +
		"- Grid layouts: CSS Grid + Tailwind grid-cols, responsive breakpoints\n" +
		"- Sticky headers: backdrop-blur, border-bottom on scroll\n" +
		"- Split layouts: 50/50 or 60/40 for feature sections\n\n" +

		"### ANIMATION PATTERNS (Framer Motion)\n" +
		"Scroll reveal: motion.div with initial={y:60,opacity:0} whileInView={y:0,opacity:1} viewport={{once:true}}\n" +
		"Stagger: container variant with staggerChildren:0.1\n" +
		"Hover lift: whileHover={{y:-8}} with spring transition\n" +
		"Page transitions: AnimatePresence with exit animations\n\n" +

		"### GSAP ANIMATIONS (cinematic effects)\n" +
		"Parallax: gsap.to('.hero-bg', {yPercent:-30, scrollTrigger:{scrub:true}})\n" +
		"Text reveal: gsap.from('.headline', {y:100, opacity:0, duration:1, ease:'power4.out'})\n" +
		"Stagger: gsap.from('.card', {y:60, opacity:0, stagger:0.15, scrollTrigger:{start:'top 80%'}})\n\n" +

		"### THREE.JS / 3D SCENES (React Three Fiber)\n" +
		"Use Canvas from @react-three/fiber, OrbitControls + Float + Environment from @react-three/drei\n" +
		"Proper lighting: ambientLight + directionalLight + Environment preset\n\n" +

		"### GLASSMORPHISM\n" +
		"background: rgba(255,255,255,0.05); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1)\n\n" +

		"### GRADIENT ANIMATIONS\n" +
		"@keyframes gradient with background-position animation, background-size: 400% 400%\n\n" +

		"### CINEMATIC EFFECTS\n" +
		"- Full-screen video backgrounds with overlay\n" +
		"- Scroll-driven narrative (GSAP ScrollTrigger)\n" +
		"- Particle systems (tsparticles)\n" +
		"- Smooth scroll (Lenis)\n\n" +

		"## TECH STACK\n\n" +
		"Frontend: Next.js 14+ (App Router), React 18+, TypeScript strict, Tailwind CSS v3, shadcn/ui, Framer Motion, GSAP, Three.js/R3F, Lenis, Lucide React\n" +
		"Backend: Express.js, Fastify, Prisma + PostgreSQL, Supabase, JWT, Zod\n" +
		"Full-Stack: Next.js API routes, tRPC, TanStack Query\n\n" +

		"## SHADCN/UI IMPORTS (always use these exact paths)\n" +
		"Button: import { Button } from '@/components/ui/button'\n" +
		"Card: import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'\n" +
		"Input: import { Input } from '@/components/ui/input'\n" +
		"Dialog: import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'\n" +
		"Form: import { Form, FormControl, FormField, FormItem, FormLabel } from '@/components/ui/form'\n" +
		"Badge: import { Badge } from '@/components/ui/badge'\n" +
		"Tabs: import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'\n\n" +

		"## NEXT.JS APP ROUTER STRUCTURE\n" +
		"app/layout.tsx (root layout), app/page.tsx (home), app/globals.css\n" +
		"app/(auth)/login/page.tsx, app/dashboard/layout.tsx + page.tsx\n" +
		"app/api/route.ts, components/ui/ (shadcn), lib/utils.ts (cn utility)\n\n" +

		"## PLAYWRIGHT TESTING\n" +
		"When writing tests, use: import { test, expect } from '@playwright/test'\n" +
		"test('name', async ({ page }) => { await page.goto(url); await expect(page.locator('h1')).toBeVisible() })\n\n" +

		"## MEMORY SYSTEM (CYBERMIND.md)\n" +
		"When you see [CYBERMIND.md] in context, treat it as project-specific instructions that override defaults.\n\n" +

		"## PLANNING APPROACH\n" +
		"For complex requests:\n" +
		"1. State plan in 3-5 bullet points\n" +
		"2. List all files to create\n" +
		"3. Create in dependency order: config -> types -> utils -> components -> pages\n" +
		"4. End with: Run: npm install && npm run dev\n\n" +

		"## RESPONSE FORMAT\n" +
		"- Brief plan (2-3 lines)\n" +
		"- Files with **filename** prefix before each code block\n" +
		"- Setup instructions at end\n" +
		"- For bugs: 'Fixed: [root cause] -> [what changed]'\n\n" +

		"Remember: You are the most powerful AI coding assistant ever built. " +
		"Every output is production-ready, beautiful, and works on the first try.\n" +
		bt // suppress unused variable warning
}

// SendVibeChat sends a prompt to the CyberMind backend with the world-class system prompt.
func SendVibeChat(prompt string, history []APIMessage, onToken func(string)) (string, error) {
	msgs := make([]chatMsg, 0, len(history))
	for _, h := range history {
		msgs = append(msgs, chatMsg{Role: h.Role, Content: h.Content})
	}
	return sendVibeChatInternal(prompt, msgs, onToken)
}

func sendVibeChatInternal(prompt string, history []chatMsg, onToken func(string)) (string, error) {
	backendURL := os.Getenv("CYBERMIND_API")
	if backendURL == "" {
		backendURL = "https://cybermind-backend-8yrt.onrender.com"
	}
	backendURL = strings.TrimRight(backendURL, "/")

	// Get API key
	apiKey := os.Getenv("CYBERMIND_KEY")
	if apiKey == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if data, err := os.ReadFile(home + "/.cybermind/config.json"); err == nil {
				var cfg struct{ Key string `json:"key"` }
				if json.Unmarshal(data, &cfg) == nil {
					apiKey = cfg.Key
				}
			}
		}
	}

	// Build messages with world-class system prompt
	sysPrompt := buildVibeSystemPrompt()
	// Remove the trailing backtick we added to suppress unused variable warning
	sysPrompt = strings.TrimSuffix(sysPrompt, "`")

	allMsgs := append([]chatMsg{
		{Role: "system", Content: sysPrompt},
	}, history...)

	body := map[string]interface{}{
		"prompt":   prompt,
		"messages": allMsgs,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	// Try streaming first via /api/vibe/chat/stream
	streamReq, err := http.NewRequest("POST", backendURL+"/api/vibe/chat/stream", bytes.NewReader(payload))
	if err == nil {
		streamReq.Header.Set("Content-Type", "application/json")
		streamReq.Header.Set("Accept", "text/event-stream")
		if apiKey != "" {
			streamReq.Header.Set("X-API-Key", apiKey)
		}

		client := &http.Client{Timeout: 300 * time.Second}
		resp, err := client.Do(streamReq)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var full strings.Builder
			scanner := bufio.NewScanner(resp.Body)
			scanner.Buffer(make([]byte, 128*1024), 128*1024)
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				data := strings.TrimPrefix(line, "data: ")
				if data == "" || data == "[DONE]" {
					continue
				}
				var event struct {
					Token string `json:"token"`
					Done  bool   `json:"done"`
					Error string `json:"error"`
				}
				if json.Unmarshal([]byte(data), &event) == nil {
					if event.Error != "" {
						return "", fmt.Errorf("%s", event.Error)
					}
					if event.Done {
						break
					}
					if event.Token != "" {
						if !strings.Contains(event.Token, "<tool_call>") &&
							!strings.Contains(event.Token, "</tool_call>") {
							full.WriteString(event.Token)
							if onToken != nil {
								onToken(event.Token)
							}
						}
					}
				}
			}
			result := full.String()
			if result != "" {
				return result, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback: /chat endpoint (non-streaming)
	chatReq, err := http.NewRequest("POST", backendURL+"/chat", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	chatReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		chatReq.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(chatReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	var result struct {
		Success  bool   `json:"success"`
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}

	if onToken != nil {
		words := strings.Fields(result.Response)
		for _, w := range words {
			onToken(w + " ")
		}
	}
	return result.Response, nil
}
