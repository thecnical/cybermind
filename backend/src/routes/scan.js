const express = require("express");
const router = express.Router();
const { getAIResponse } = require("../services/aiRouter");
const { logRequest } = require("../utils/requestLogger");

// POST /scan — AI-powered scan guidance
router.post("/", async (req, res) => {
  const { target, type, options } = req.body;

  if (!target) return res.status(400).json({ success: false, error: "target is required" });

  const scanTypes = {
    quick:    `Quick nmap scan of ${target}: top 1000 ports, service detection, OS detection`,
    full:     `Full nmap scan of ${target}: all 65535 ports, service versions, scripts, OS detection`,
    stealth:  `Stealth SYN scan of ${target} using nmap: avoid detection, slow timing`,
    web:      `Web application scan of ${target}: nikto, whatweb, wafw00f, directory bruteforce with ffuf`,
    vuln:     `Vulnerability scan of ${target}: nmap vuln scripts, nuclei templates, searchsploit`,
    subdomain:`Subdomain enumeration for ${target}: subfinder, amass, dnsx, httpx pipeline`,
    network:  `Network discovery scan for ${target} subnet: live hosts, open ports, services`,
    ad:       `Active Directory enumeration of ${target}: ldap, smb, kerberos, bloodhound`,
  };

  const scanPrompt = scanTypes[type] || `Perform a ${type || "comprehensive"} scan of ${target}${options ? `. Additional context: ${options}` : ""}`;
  const fullPrompt = `${scanPrompt}. Provide exact Kali Linux commands with all flags, step by step.`;

  try {
    const { response, provider, model, time } = await getAIResponse(fullPrompt);
    logRequest(req, "success");
    return res.json({ success: true, target, type: type || "custom", response, provider, model, time });
  } catch (err) {
    logRequest(req, "fail");
    return res.status(502).json({ success: false, error: "AI unavailable" });
  }
});

module.exports = router;
