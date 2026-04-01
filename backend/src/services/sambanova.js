const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

// SambaNova Cloud — OpenAI-compatible API
const SAMBANOVA_API_BASE = "https://api.sambanova.ai/v1/chat/completions";
const TIMEOUT_MS = 60000;

/**
 * Query a SambaNova model.
 * @param {string} model - SambaNova model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function querySambaNova(model, prompt, apiKey) {
  const response = await axios.post(
    SAMBANOVA_API_BASE,
    {
      model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: prompt },
      ],
      max_tokens: 2048,
      temperature: 0.7,
      top_p: 0.95,
    },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: TIMEOUT_MS,
    }
  );

  const text = response.data?.choices?.[0]?.message?.content;
  if (!text) throw new Error("Empty response from SambaNova");
  return text.trim();
}

module.exports = { querySambaNova };
