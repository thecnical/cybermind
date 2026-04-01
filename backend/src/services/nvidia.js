const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

const NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1/chat/completions";
const TIMEOUT_MS = 60000;

async function queryNvidia(model, prompt, apiKey) {
  const response = await axios.post(
    NVIDIA_API_BASE,
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
  if (!text) throw new Error("Empty response from NVIDIA");
  return text.trim();
}

module.exports = { queryNvidia };
