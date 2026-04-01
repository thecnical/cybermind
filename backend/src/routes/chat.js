const express = require("express");
const router = express.Router();
const { getAIResponse } = require("../services/aiRouter");
const logger = require("../utils/logger");
const { logRequest } = require("../utils/requestLogger");

const MAX_PROMPT_LENGTH = 4000;
const REQUEST_TIMEOUT_MS = 120000;

// Identity questions — answer directly, no AI call needed
const IDENTITY_PATTERNS = [
  /who are you/i,
  /what are you/i,
  /what is your name/i,
  /who made you/i,
  /who created you/i,
  /who built you/i,
  /your name/i,
  /introduce yourself/i,
  /tell me about yourself/i,
];

const IDENTITY_RESPONSE = `I am CyberMind, an AI-powered cybersecurity assistant created by Chandan Pandey (github.com/thecnical). I specialize in offensive and defensive cybersecurity — from reconnaissance and exploitation to forensics and hardening. Ask me anything about cybersecurity.`;

// Abuse patterns: repeated chars, spam keywords
const ABUSE_PATTERNS = [
  /(.)\1{49,}/,           // same char repeated 50+ times
  /\b(test\s*){10,}/i,    // "test" repeated 10+ times
];

function isAbusive(prompt) {
  return ABUSE_PATTERNS.some((p) => p.test(prompt));
}

// POST /chat
router.post("/", async (req, res) => {
  const { prompt } = req.body;

  // Input validation
  if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
    logRequest(req, "fail");
    return res.status(400).json({ success: false, error: "Invalid input" });
  }

  if (prompt.trim().length > MAX_PROMPT_LENGTH) {
    logRequest(req, "fail");
    return res.status(400).json({ success: false, error: "Invalid input" });
  }

  if (isAbusive(prompt)) {
    logRequest(req, "blocked");
    return res.status(400).json({ success: false, error: "Invalid input" });
  }

  // Identity check — answer directly
  if (IDENTITY_PATTERNS.some((p) => p.test(prompt))) {
    logRequest(req, "identity");
    return res.json({
      success: true,
      response: IDENTITY_RESPONSE,
      provider: "direct",
      model: "identity",
      time: "0.01s",
    });
  }

  // Request timeout guard
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    if (!res.headersSent) {
      logRequest(req, "timeout");
      res.status(504).json({ success: false, error: "Request timed out. Try again." });
    }
  }, REQUEST_TIMEOUT_MS);

  try {
    const { response, provider, model, time } = await getAIResponse(prompt.trim());

    if (timedOut) return; // response arrived too late

    clearTimeout(timeout);
    logRequest(req, "success");
    return res.json({ success: true, response, provider, model, time });
  } catch (err) {
    clearTimeout(timeout);
    if (timedOut) return;
    logger.error("AI router error:", err.message);
    logRequest(req, "fail");
    return res.status(502).json({ success: false, error: "Server error. Try again later." });
  }
});

module.exports = router;
