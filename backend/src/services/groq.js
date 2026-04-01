const axios = require("axios");
const SYSTEM_PROMPT = require("../config/systemPrompt");

const GROQ_API_BASE = "https://api.groq.com/openai/v1/chat/completions";
const TIMEOUT_MS = 60000;

async function queryGroq(model, prompt, apiKey) {
  const response = await axios.post(
    GROQ_API_BASE,
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
  if (!text) throw new Error("Empty response from Groq");
  return text.trim();
}

module.exports = { queryGroq };
