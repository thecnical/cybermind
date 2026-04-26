/**
 * CyberMind Edge Worker — Cloudflare Workers
 *
 * Always-on fallback for the Render backend.
 * Handles: /ping, /agent/decide, /chat (lightweight)
 * Heavy routes (recon analysis, abhimanyu) proxy to Render.
 *
 * Deploy: wrangler deploy
 * URL: https://cybermind-api.chandanabhay458.workers.dev
 */

const RENDER_BACKEND = "https://cybermind-backend-8yrt.onrender.com";

// Routes handled locally (no Render needed)
const LOCAL_ROUTES = new Set(["/ping", "/wake", "/health"]);

// Routes that need AI — proxy to Render, but with fast timeout
const AI_ROUTES = new Set([
  "/agent/decide",
  "/chat",
  "/plan",
  "/adversarial/think",
  "/adversarial/refine",
  "/nuclei-template",
  "/poc",
  "/bug-alert",
]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers for CLI requests
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Device-OS, X-Device-ID, X-User-Name, X-User-Plan, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // ── Local routes — instant response ──────────────────────────────────
    if (path === "/ping" || path === "/wake") {
      return Response.json({ ok: true, edge: true }, { headers: corsHeaders });
    }

    if (path === "/health") {
      return Response.json({
        status: "ok",
        edge: true,
        region: request.cf?.colo || "unknown",
        timestamp: new Date().toISOString(),
      }, { headers: corsHeaders });
    }

    // ── /agent/decide — lightweight local decision ────────────────────────
    // If Render is down, make a basic decision locally without AI
    if (path === "/agent/decide" && request.method === "POST") {
      try {
        const body = await request.json();

        // Try Render first with short timeout
        const renderResult = await tryRender(path, body, request, 8000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // Render unavailable — make local decision
        const decision = makeLocalDecision(body);
        return Response.json({ success: true, decision }, { headers: corsHeaders });

      } catch (e) {
        return Response.json({
          success: true,
          decision: { action: "hunt", reason: "edge fallback", vuln_focus: "all", confidence: 50 }
        }, { headers: corsHeaders });
      }
    }

    // ── /osint-deep — proxy to Render, edge fallback with structured prompt ──
    if (path === "/osint-deep" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 20000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        // Fallback: route to /chat with structured prompt
        const prompt = buildOSINTPrompt(body);
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 20000);
        if (chatResult) {
          return new Response(chatResult.body, {
            status: chatResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── /reveng — proxy to Render, edge fallback ──────────────────────────
    if (path === "/reveng" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 20000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        const prompt = buildRevEngPrompt(body);
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 20000);
        if (chatResult) {
          return new Response(chatResult.body, {
            status: chatResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── /locate — proxy to Render, edge fallback ──────────────────────────
    if (path === "/locate" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 15000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        const prompt = buildLocatePrompt(body);
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 15000);
        if (chatResult) {
          return new Response(chatResult.body, {
            status: chatResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── /api/attack-session/* — proxy to Render for dashboard tracking ───
    if (path.startsWith("/api/attack-session/") && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 10000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        // Silently succeed if Render is down — non-critical tracking
        return Response.json({ success: true, edge: true }, { headers: corsHeaders });
      } catch {
        return Response.json({ success: true, edge: true }, { headers: corsHeaders });
      }
    }

    // ── /api/vibe-hack/stream — proxy SSE stream to Render ───────────────
    if (path === "/api/vibe-hack/stream") {
      try {
        const renderURL = RENDER_BACKEND + path + url.search;
        const proxyReq = new Request(renderURL, {
          method: request.method,
          headers: {
            ...Object.fromEntries(request.headers),
            "Accept": "text/event-stream",
          },
        });
        const resp = await fetch(proxyReq, { signal: AbortSignal.timeout(300000) });
        return new Response(resp.body, {
          status: resp.status,
          headers: {
            ...corsHeaders,
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
          },
        });
      } catch (e) {
        return Response.json({ success: false, error: "Stream unavailable" }, { status: 503, headers: corsHeaders });
      }
    }

    // ── /api/chain/analyze — proxy to Render ─────────────────────────────
    if (path === "/api/chain/analyze" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 30000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        // Fallback: route to /chat
        const bugs = (body.bugs || []).slice(0, 10);
        const prompt = `Vulnerability Chain Analysis for ${body.target}:\n\nBugs found:\n${bugs.map((b, i) => `${i+1}. [${b.severity?.toUpperCase()}] ${b.title} at ${b.url}`).join("\n")}\n\nGenerate exploit chains. Format each as:\nChain N: VULN1 + VULN2 -> Impact\nPoC: step-by-step exploitation\nCVSS Uplift: X.X`;
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 30000);
        if (chatResult) return new Response(chatResult.body, { status: chatResult.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── /api/red-team/phase — proxy to Render ────────────────────────────
    if (path === "/api/red-team/phase" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 60000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        // Fallback: route to /chat
        const phaseNames = ["OSINT", "Phishing Prep", "Initial Access", "Lateral Movement", "Lateral Movement (continued)", "Persistence", "Report"];
        const phaseName = phaseNames[(body.phase || 1) - 1] || `Phase ${body.phase}`;
        const prompt = `Red Team Campaign - ${body.company}\nPhase ${body.phase}: ${phaseName}\nScope: ${JSON.stringify(body.scope)}\n${body.prior_summaries?.length ? `Prior phases:\n${body.prior_summaries.join("\n")}` : ""}\n\nProvide detailed guidance for this phase including: objectives, tools, techniques, MITRE ATT&CK TTPs, and expected outcomes.`;
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 60000);
        if (chatResult) return new Response(chatResult.body, { status: chatResult.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── /api/devsec/analyze — proxy to Render ────────────────────────────
    if (path === "/api/devsec/analyze" && request.method === "POST") {
      try {
        const body = await request.json();
        const renderResult = await tryRender(path, body, request, 30000);
        if (renderResult) {
          return new Response(renderResult.body, {
            status: renderResult.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        // Fallback: route to /chat
        const prompt = `DevSec Analysis for: ${body.target}\n\nFindings:\n${(body.findings || "").slice(0, 20000)}\n\nProvide: 1) Critical secrets/credentials found 2) SAST vulnerabilities with severity 3) Vulnerable dependencies with CVEs 4) Remediation priority list 5) Security score (0-100)`;
        const chatResult = await tryRender("/chat", { prompt, messages: [] }, request, 30000);
        if (chatResult) return new Response(chatResult.body, { status: chatResult.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        return Response.json({ success: false, error: "Backend unavailable" }, { status: 503, headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, error: e.message }, { status: 500, headers: corsHeaders });
      }
    }

    // ── All other routes — proxy to Render ───────────────────────────────
    try {
      const renderURL = RENDER_BACKEND + path + url.search;
      const proxyReq = new Request(renderURL, {
        method: request.method,
        headers: request.headers,
        body: request.method !== "GET" ? request.body : undefined,
      });

      const resp = await fetch(proxyReq, { signal: AbortSignal.timeout(25000) });
      const respBody = await resp.text();

      return new Response(respBody, {
        status: resp.status,
        headers: {
          ...corsHeaders,
          "Content-Type": resp.headers.get("Content-Type") || "application/json",
          "X-Served-By": "cybermind-edge",
        },
      });
    } catch (e) {
      // Render is down — return edge error
      return Response.json({
        success: false,
        error: "Backend temporarily unavailable. Retrying...",
        edge: true,
      }, { status: 503, headers: corsHeaders });
    }
  }
};

// makeLocalDecision — pure logic, no AI needed
function makeLocalDecision(state) {
  const d = {
    action: "hunt",
    reason: "edge fallback decision",
    vuln_focus: "all",
    tools_add: [],
    tools_skip: [],
    waf_bypass: "",
    depth: "deep",
    next_target: "",
    confidence: 55,
    notes: "AI backend unavailable — using edge logic",
  };

  if (!state.recon_done) {
    d.action = "recon";
    d.reason = "Start with recon";
  } else if (!state.hunt_done) {
    d.action = "hunt";
    d.reason = "Recon done — hunt for vulns";
    // Smart vuln focus from tech stack
    const tech = (state.technologies || []).join(" ").toLowerCase();
    if (tech.includes("wordpress") || tech.includes("php")) d.vuln_focus = "rce";
    else if (tech.includes("react") || tech.includes("angular")) d.vuln_focus = "xss";
    else if (tech.includes("node") || tech.includes("express")) d.vuln_focus = "ssrf";
    // WAF bypass
    if (state.waf_detected) {
      d.waf_bypass = "random-agent,delay=1";
      d.tools_skip = ["masscan"]; // too noisy with WAF
    }
  } else if (state.bugs_found > 0 && !state.abhi_done) {
    d.action = "exploit";
    d.reason = `${state.bugs_found} bugs found — exploiting`;
    d.vuln_focus = (state.bug_types || [])[0] || "all";
  } else if (state.bugs_found > 0) {
    d.action = "poc";
    d.reason = "Generate PoC for confirmed bugs";
  } else {
    d.action = "next_target";
    d.reason = "No bugs found — try next target";
  }

  return d;
}

async function tryRender(path, body, originalRequest, timeoutMs) {
  try {
    const resp = await fetch(RENDER_BACKEND + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": originalRequest.headers.get("X-API-Key") || "",
        "X-Device-OS": originalRequest.headers.get("X-Device-OS") || "",
        "X-Device-ID": originalRequest.headers.get("X-Device-ID") || "",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (resp.ok) {
      return { status: resp.status, body: await resp.text() };
    }
    return null;
  } catch {
    return null;
  }
}

// buildOSINTPrompt — builds AI prompt from OSINT payload for edge fallback
function buildOSINTPrompt(p) {
  let prompt = `OSINT Deep Scan for: ${p.target} (type: ${p.target_type})\n`;
  prompt += `Tools: ${(p.tools_run || []).join(", ")}\n\n`;
  if (p.emails_found?.length) prompt += `Emails: ${p.emails_found.slice(0,10).join(", ")}\n`;
  if (p.subdomains_found?.length) prompt += `Subdomains: ${p.subdomains_found.length} found\n`;
  if (p.social_profiles?.length) prompt += `Social profiles:\n${p.social_profiles.slice(0,5).join("\n")}\n`;
  if (p.breaches_found?.length) prompt += `BREACHES FOUND:\n${p.breaches_found.slice(0,5).join("\n")}\n`;
  if (p.employees_found?.length) prompt += `Employees: ${p.employees_found.length} found\n`;
  if (p.github_leaks?.length) prompt += `GitHub leaks: ${p.github_leaks.length}\n`;
  const raw = (p.raw || "").slice(0, 20000);
  if (raw) prompt += `\nFindings:\n${raw}`;
  prompt += "\n\nProvide: 1) Digital footprint summary 2) Attack surface 3) Breach/credential risk 4) Social engineering vectors 5) Pentest next steps 6) MITRE ATT&CK mapping";
  return prompt;
}

// buildRevEngPrompt — builds AI prompt from RevEng payload for edge fallback
function buildRevEngPrompt(p) {
  let prompt = `Reverse Engineering Analysis for: ${p.target}\n`;
  prompt += `Mode: ${p.analysis_mode} | File: ${p.file_type} | Arch: ${p.architecture} ${p.bitness}\n`;
  prompt += `Security: PIE=${p.pie} NX=${p.nx} Canary=${p.canary} RELRO=${p.relro} Stripped=${p.stripped}\n`;
  if (p.vuln_functions?.length) prompt += `Vulnerable functions: ${p.vuln_functions.join(", ")}\n`;
  if (p.yara_matches?.length) prompt += `YARA matches: ${p.yara_matches.length}\n`;
  if (p.rop_gadgets?.length) prompt += `ROP gadgets: ${p.rop_gadgets.length}\n`;
  if (p.suspicious_strings?.length) prompt += `Suspicious strings:\n${p.suspicious_strings.slice(0,10).join("\n")}\n`;
  prompt += `Tools: ${(p.tools_run || []).join(", ")}\n`;
  const raw = (p.raw || "").slice(0, 40000);
  if (raw) prompt += `\nAnalysis:\n${raw}`;
  prompt += "\n\nProvide: 1) Binary purpose 2) Vulnerabilities (BOF, format string, UAF) 3) Exploit approach (ROP, shellcode) 4) Malware indicators 5) CVEs for libraries 6) Key function analysis";
  return prompt;
}

// buildLocatePrompt — builds AI prompt from Locate payload for edge fallback
function buildLocatePrompt(p) {
  let prompt = `Geolocation Analysis for: ${p.target} (type: ${p.target_type})\n`;
  if (p.city || p.country) prompt += `Location: ${p.city}, ${p.country}\n`;
  if (p.isp) prompt += `ISP: ${p.isp}\n`;
  if (p.coordinates?.length) prompt += `GPS: ${p.coordinates.join(" | ")}\n`;
  if (p.exif_gps) prompt += `EXIF GPS: ${p.exif_gps}\n`;
  if (p.wifi_ssids?.length) prompt += `WiFi SSIDs: ${p.wifi_ssids.length} captured\n`;
  if (p.cell_towers?.length) prompt += `Cell towers: ${p.cell_towers.length} captured\n`;
  prompt += `Tools: ${(p.tools_run || []).join(", ")}\n`;
  const raw = (p.raw || "").slice(0, 10000);
  if (raw) prompt += `\nData:\n${raw}`;
  prompt += "\n\nProvide: 1) Physical location summary 2) Network infrastructure 3) Attack surface 4) Privacy exposure 5) Follow-up actions";
  return prompt;
}
