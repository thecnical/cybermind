const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

const OPENROUTER_API_BASE = "https://openrouter.ai/api/v1/chat/completions";
const TIMEOUT_MS = 60000;

async function queryOpenRouter(model, prompt, apiKey) {
  const response = await axios.post(
    OPENROUTER_API_BASE,
    {
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: prompt },
      ],
      max_tokens: 2048,
      temperature: 0.7,
    },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cybermind.thecnical.dev",
        "X-Title": "CyberMind",
      },
      timeout: TIMEOUT_MS,
    }
  );

  const text = response.data?.choices?.[0]?.message?.content;
  if (!text) throw new Error("Empty response from OpenRouter");
  return text.trim();
}

module.exports = { queryOpenRouter };
