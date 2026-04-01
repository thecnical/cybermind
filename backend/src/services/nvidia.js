const axios = require("axios");

const NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1/chat/completions";
const TIMEOUT_MS = 60000;

/**
 * Query an NVIDIA NIM model.
 * @param {string} model - NVIDIA model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function queryNvidia(model, prompt, apiKey) {
  const response = await axios.post(
    NVIDIA_API_BASE,
    {
      model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 512,
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
  if (!text) throw new Error("Empty response from NVIDIA");
  return text.trim();
}

module.exports = { queryNvidia };
