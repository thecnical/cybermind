// Round-robin key rotation per provider
const counters = {};

/**
 * Parse a comma-separated env var into an array of keys.
 * @param {string} envVar - e.g. "HF_KEYS"
 * @returns {string[]}
 */
function loadKeys(envVar) {
  const raw = process.env[envVar] || "";
  return raw.split(",").map((k) => k.trim()).filter(Boolean);
}

/**
 * Return the next available key for a provider using round-robin.
 * @param {string} provider - e.g. "huggingface"
 * @returns {string}
 */
function getNextKey(provider) {
  const envMap = {
    huggingface: "HF_KEYS",
    nvidia:      "NVIDIA_KEYS",
    bytez:       "BYTEZ_KEYS",
    openrouter:  "OPENROUTER_KEYS",
    sambanova:   "SAMBANOVA_KEYS",
    aicc:        "AICC_KEYS",
  };

  const envVar = envMap[provider];
  if (!envVar) throw new Error(`Unknown provider: ${provider}`);

  const keys = loadKeys(envVar);
  if (keys.length === 0) throw new Error(`No API keys found for provider: ${provider}`);

  if (counters[provider] === undefined) counters[provider] = 0;
  const key = keys[counters[provider] % keys.length];
  counters[provider]++;
  return key;
}

module.exports = { getNextKey };
