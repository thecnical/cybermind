const models = require("../config/models");
const { getNextKey } = require("../utils/keyRotation");
const { isValidResponse } = require("../utils/responseSelector");
const { queryHuggingFace } = require("./huggingface");
const { queryNvidia } = require("./nvidia");
const { queryBytez } = require("./bytez");
const { queryOpenRouter } = require("./openrouter");
const { querySambaNova } = require("./sambanova");
const { querySambaNova } = require("./sambanova");
const logger = require("../utils/logger");

const TIMEOUT_MS = 60000;

// Map provider → query function
const providerFn = {
  sambanova:   querySambaNova,
  nvidia:      queryNvidia,
  openrouter:  queryOpenRouter,
  huggingface: queryHuggingFace,
  bytez:       queryBytez,
};

/**
 * Wrap a promise with a timeout rejection.
 * @param {Promise} promise
 * @param {number} ms
 * @returns {Promise}
 */
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), ms)
    ),
  ]);
}

/**
 * Try all models for a single provider sequentially.
 * Returns { response, provider, model } or throws if all fail.
 * @param {string} provider
 * @param {string} prompt
 * @returns {Promise<{ response: string, provider: string, model: string }>}
 */
async function tryProvider(provider, prompt) {
  const providerModels = models[provider];
  if (!providerModels || providerModels.length === 0) {
    throw new Error(`No models configured for ${provider}`);
  }

  for (const { name, model } of providerModels) {
    let apiKey;
    try {
      apiKey = getNextKey(provider);
    } catch {
      throw new Error(`No API keys for ${provider}`);
    }

    try {
      logger.info(`[${provider}] trying ${name}`);
      const fn = providerFn[provider];
      const response = await withTimeout(fn(model, prompt, apiKey), TIMEOUT_MS);

      if (!isValidResponse(response)) {
        logger.warn(`[${provider}/${name}] invalid response, skipping`);
        continue;
      }

      return { response, provider, model: name };
    } catch (err) {
      logger.warn(`[${provider}/${name}] failed: ${err.message}`);
    }
  }

  throw new Error(`All models failed for provider: ${provider}`);
}

/**
 * Core AI Router — runs all providers in parallel, returns fastest valid response.
 * @param {string} prompt
 * @returns {Promise<{ response: string, provider: string, model: string, time: string }>}
 */
async function getAIResponse(prompt) {
  const start = Date.now();

  const providerRaces = Object.keys(providerFn).map((provider) =>
    tryProvider(provider, prompt)
  );

  try {
    const result = await Promise.any(providerRaces);
    const time = ((Date.now() - start) / 1000).toFixed(2) + "s";
    logger.info(`Response from [${result.provider}/${result.model}] in ${time}`);
    return { ...result, time };
  } catch {
    throw new Error("All AI providers failed");
  }
}

module.exports = { getAIResponse };
