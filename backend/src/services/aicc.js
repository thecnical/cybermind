const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

// api.ai.cc — OpenAI-compatible API
const AICC_API_BASE = "https://api.ai.cc/v1/chat/completions";
const TIMEOUT_MS = 60000;

/**
 * Query an api.ai.cc model.
 * @param {string} model - model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function queryAiCC(model, prompt, apiKey) {
  const response = await axios.post(
    AICC_API_BASE,
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
  if (!text) throw new Error("Empty response from ai.cc");
  return text.trim();
}

module.exports = { queryAiCC };
