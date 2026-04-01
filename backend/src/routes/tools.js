const express = require("express");
const router = express.Router();
const { getAIResponse } = require("../services/aiRouter");
const { logRequest } = require("../utils/requestLogger");

// Kali tool categories with descriptions
const KALI_TOOLS = {
  recon:       ["nmap","masscan","rustscan","amass","subfinder","httpx","theHarvester","shodan","nuclei","ffuf","gobuster","feroxbuster","whatweb","wafw00f","nikto","dnsx","naabu","katana"],
  exploitation:["metasploit","sqlmap","xsstrike","dalfox","commix","tplmap","searchsploit","burpsuite","ghauri","wapiti"],
  passwords:   ["hashcat","john","hydra","medusa","kerbrute","cewl","crunch","mimikatz","secretsdump","spray"],
  wireless:    ["aircrack-ng","wifite","bettercap","hcxdumptool","hostapd-wpe","eaphammer"],
  postexploit: ["meterpreter","empire","sliver","chisel","ligolo-ng","linpeas","winpeas","bloodhound","impacket","crackmapexec","evil-winrm"],
  forensics:   ["volatility3","autopsy","binwalk","ghidra","radare2","gdb","pwntools","wireshark","tshark"],
  web:         ["burpsuite","sqlmap","ffuf","nuclei","wpscan","nikto","xsstrike","dalfox","jwt_tool","corsy"],
  ad:          ["bloodhound","impacket","crackmapexec","kerbrute","rubeus","mimikatz","responder","ntlmrelayx","evil-winrm"],
};

// GET /tools — list all tools by category
router.get("/", (req, res) => {
  res.json({ success: true, tools: KALI_TOOLS });
});

// GET /tools/:category — list tools in a category
router.get("/:category", (req, res) => {
  const { category } = req.params;
  if (!KALI_TOOLS[category]) {
    return res.status(404).json({ success: false, error: `Unknown category: ${category}` });
  }
  res.json({ success: true, category, tools: KALI_TOOLS[category] });
});

// POST /tools/help — get AI help for a specific tool
router.post("/help", async (req, res) => {
  const { tool, task } = req.body;
  if (!tool) return res.status(400).json({ success: false, error: "tool is required" });

  const prompt = task
    ? `Kali Linux: How to use ${tool} for: ${task}. Give exact commands with flags.`
    : `Kali Linux: Complete guide for ${tool}. Show most useful commands with exact flags and examples.`;

  try {
    const { response, provider, model, time } = await getAIResponse(prompt);
    logRequest(req, "success");
    return res.json({ success: true, tool, response, provider, model, time });
  } catch (err) {
    logRequest(req, "fail");
    return res.status(502).json({ success: false, error: "AI unavailable" });
  }
});

module.exports = router;
