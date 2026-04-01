const axios = require("axios");

const BYTEZ_API_BASE = "https://api.bytez.com/models";
const TIMEOUT_MS = 60000;

/**
 * Query a Bytez-hosted model.
 * @param {string} model - Bytez model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function queryBytez(model, prompt, apiKey) {
  const response = await axios.post(
    `${BYTEZ_API_BASE}/${model}/v2/chat`,
    {
      messages: [{ role: "user", content: prompt }],
    },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: TIMEOUT_MS,
    }
  );

  const text = response.data?.output?.[0]?.content
    ?? response.data?.choices?.[0]?.message?.content;

  if (!text) throw new Error("Empty response from Bytez");
  return text.trim();
}

module.exports = { queryBytez };
