module.exports = {
  // --- Tier 1: Fastest & most powerful ---
  groq: [
    { name: "llama-3.3-70b",     model: "llama-3.3-70b-versatile" },
    { name: "kimi-k2",           model: "moonshotai/kimi-k2-instruct" },
    { name: "qwen3-32b",         model: "qwen/qwen3-32b" },
    { name: "llama-4-scout",     model: "meta-llama/llama-4-scout-17b-16e-instruct" },
    { name: "gpt-oss-120b",      model: "openai/gpt-oss-120b" },
  ],
  cerebras: [
    { name: "qwen3-235b",        model: "qwen-3-235b-a22b-instruct-2507" },
    { name: "llama3.1-8b",       model: "llama3.1-8b" },
  ],
  aicc: [
    { name: "gpt-5.4-pro",              model: "gpt-5.4-pro" },
    { name: "claude-opus-4-thinking",   model: "claude-opus-4-20250514-thinking" },
    { name: "deepseek-v3.2",            model: "deepseek-v3.2" },
    { name: "gemini-2.5-flash",         model: "gemini-2.5-flash" },
    { name: "grok-4.1-fast",            model: "grok-4.1-fast" },
    { name: "kimi-k2.5",                model: "kimi-k2.5" },
  ],
  // --- Tier 2: Strong fallbacks ---
  sambanova: [
    { name: "llama3.3-70b",      model: "Meta-Llama-3.3-70B-Instruct" },
    { name: "llama3.1-405b",     model: "Meta-Llama-3.1-405B-Instruct" },
    { name: "deepseek-r1",       model: "DeepSeek-R1" },
    { name: "qwen3-32b",         model: "Qwen3-32B" },
  ],
  mistral: [
    { name: "mistral-large",     model: "mistral-large-latest" },
    { name: "ministral-14b",     model: "ministral-14b-latest" },
    { name: "ministral-8b",      model: "ministral-8b-latest" },
    { name: "devstral-medium",   model: "devstral-medium-2507" },
  ],
  nvidia: [
    { name: "qwen2.5-uncensored",     model: "Orion-zhen/Qwen2.5-7B-Instruct-Uncensored" },
    { name: "deepseek-r1-uncensored", model: "DeepSeek-R1-Distill-Qwen-32B-Uncensored" },
    { name: "llama3",                 model: "meta/llama3-8b-instruct" },
    { name: "mixtral",                model: "mistralai/mixtral-8x7b-instruct" },
  ],
  openrouter: [
    { name: "deepseek", model: "deepseek/deepseek-chat" },
  ],
  // --- Tier 3: Last resort ---
  huggingface: [
    { name: "nous-hermes", model: "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" },
    { name: "mistral",     model: "mistralai/Mistral-7B-Instruct-v0.3" },
    { name: "falcon",      model: "tiiuae/falcon-7b-instruct" },
  ],
  bytez: [
    { name: "bytez-mistral", model: "mistralai/Mistral-7B-Instruct-v0.1" },
  ],
};
