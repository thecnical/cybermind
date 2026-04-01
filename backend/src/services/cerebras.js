const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

const CEREBRAS_API_BASE = "https://api.cerebras.ai/v1/chat/completions";
const TIMEOUT_MS = 60000;

async function queryCerebras(model, prompt, apiKey) {
  const response = await axios.post(
    CEREBRAS_API_BASE,
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
  if (!text) throw new Error("Empty response from Cerebras");
  return text.trim();
}

module.exports = { queryCerebras };
