const axios = require("axios");

const HF_API_BASE = "https://api-inference.huggingface.co/models";
const TIMEOUT_MS = 60000;

/**
 * Query a HuggingFace model.
 * @param {string} model - HF model ID
 * @param {string} prompt
 * @param {string} apiKey
 * @returns {Promise<string>}
 */
async function queryHuggingFace(model, prompt, apiKey) {
  const response = await axios.post(
    `${HF_API_BASE}/${model}`,
    { inputs: prompt },
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: TIMEOUT_MS,
    }
  );

  const data = response.data;

  if (Array.isArray(data) && data[0]?.generated_text) {
    return data[0].generated_text.trim();
  }
  if (data?.generated_text) return data.generated_text.trim();
  if (typeof data === "string" && data.trim()) return data.trim();

  throw new Error("Empty or unrecognized response from HuggingFace");
}

module.exports = { queryHuggingFace };
