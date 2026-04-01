const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

const BYTEZ_API_BASE = "https://api.bytez.com/models";
const TIMEOUT_MS = 60000;

async function queryBytez(model, prompt, apiKey) {
  const response = await axios.post(
    `${BYTEZ_API_BASE}/${model}/v2/chat`,
    {
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: prompt },
      ],
      max_tokens: 2048,
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
