module.exports = {
  huggingface: [
    { name: "dolphin",     model: "ehartford/dolphin-2.6-mistral-7b" },
    { name: "nous-hermes", model: "NousResearch/Nous-Hermes-2-Mistral-7B-DPO" },
    { name: "openhermes",  model: "teknium/OpenHermes-2.5-Mistral-7B" },
    { name: "mistral",     model: "mistralai/Mistral-7B-Instruct-v0.3" },
    { name: "wizardlm",    model: "TheBloke/WizardLM-7B-Uncensored-GPTQ" },
    { name: "falcon",      model: "tiiuae/falcon-7b-instruct" },
  ],
  nvidia: [
    { name: "qwen2.5-uncensored",  model: "Orion-zhen/Qwen2.5-7B-Instruct-Uncensored" },
    { name: "deepseek-r1-uncensored", model: "DeepSeek-R1-Distill-Qwen-32B-Uncensored" },
    { name: "llama3",    model: "meta/llama3-8b-instruct" },
    { name: "mixtral",   model: "mistralai/mixtral-8x7b-instruct" },
    { name: "nemotron",  model: "nvidia/nemotron-4-340b-instruct" },
  ],
  bytez: [
    { name: "bytez-mistral", model: "mistralai/Mistral-7B-Instruct-v0.1" },
    { name: "bytez-llama",   model: "meta-llama/Llama-2-7b-chat-hf" },
  ],
  openrouter: [
    { name: "deepseek", model: "deepseek/deepseek-chat" },
  ],
  sambanova: [
    { name: "llama3.3-70b",     model: "Meta-Llama-3.3-70B-Instruct" },
    { name: "llama3.1-405b",    model: "Meta-Llama-3.1-405B-Instruct" },
    { name: "deepseek-r1",      model: "DeepSeek-R1" },
    { name: "qwen3-32b",        model: "Qwen3-32B" },
  ],
  aicc: [
    { name: "gpt-5.4-pro",              model: "gpt-5.4-pro" },
    { name: "claude-opus-4-thinking",   model: "claude-opus-4-20250514-thinking" },
    { name: "deepseek-v3.2",            model: "deepseek-v3.2" },
    { name: "gemini-2.5-flash",         model: "gemini-2.5-flash" },
    { name: "grok-4.1-fast",            model: "grok-4.1-fast" },
    { name: "kimi-k2.5",                model: "kimi-k2.5" },
  ],
};
