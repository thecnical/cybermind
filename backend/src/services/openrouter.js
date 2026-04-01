const axios = require("axios");

const OPENROUTER_API_BASE = "https://openrouter.ai/api/v1/chat/completions";
const TIMEOUT_MS = 60000;

/**
 * Query an OpenRouter model.
 * @param {string} model - OpenRouter model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function queryOpenRouter(model, prompt, apiKey) {
  const response = await axios.post(
    OPENROUTER_API_BASE,
    {
      model,
      messages: [{ role: "user", content: prompt }],
    },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://cybermind.local",
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
