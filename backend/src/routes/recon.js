const express = require("express");
const router = express.Router();
const { getAIResponse } = require("../services/aiRouter");
const { logRequest } = require("../utils/requestLogger");

// POST /recon — AI-powered recon guidance
router.post("/", async (req, res) => {
  const { target, type } = req.body;
  if (!target) return res.status(400).json({ success: false, error: "target is required" });

  const reconTypes = {
    passive:   `Passive OSINT recon for ${target}: no direct contact, use shodan, censys, google dorks, theHarvester, whois, dnsdumpster, waybackurls, gau, github dorking`,
    active:    `Active recon for ${target}: nmap, masscan, rustscan, httpx, nuclei, ffuf, gobuster — full command pipeline`,
    subdomain: `Subdomain enumeration for ${target}: subfinder, amass, assetfinder, dnsx, puredns, httpx — full pipeline with commands`,
    osint:     `Full OSINT investigation for ${target}: emails, employees, infrastructure, social media, leaked credentials, pastebin, github`,
    web:       `Web recon for ${target}: technology stack, directories, parameters, endpoints, JS files, API keys in source`,
    network:   `Network recon for ${target}: topology mapping, live hosts, open ports, services, banners`,
  };

  const prompt = reconTypes[type] || `Comprehensive recon for ${target}. Provide exact Kali Linux commands.`;

  try {
    const { response, provider, model, time } = await getAIResponse(prompt);
    logRequest(req, "success");
    return res.json({ success: true, target, type: type || "full", response, provider, model, time });
  } catch (err) {
    logRequest(req, "fail");
    return res.status(502).json({ success: false, error: "AI unavailable" });
  }
});

module.exports = router;
