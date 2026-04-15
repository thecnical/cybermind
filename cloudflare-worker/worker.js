/**
 * CyberMind Edge Worker — Cloudflare Workers
 *
 * Always-on fallback for the Render backend.
 * Handles: /ping, /agent/decide, /chat (lightweight)
 * Heavy routes (recon analysis, abhimanyu) proxy to Render.
 *
 * Deploy: wrangler deploy
 * URL: https://cybermind-api.thecnical.workers.dev
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
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Device-OS, X-Device-ID, X-User-Name",
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
