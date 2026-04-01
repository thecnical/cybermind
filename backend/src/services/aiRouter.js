const models = require("../config/models");
const { getNextKey } = require("../utils/keyRotation");
const { isValidResponse } = require("../utils/responseSelector");
const { queryGroq }       = require("./groq");
const { queryCerebras }   = require("./cerebras");
const { queryAiCC }       = require("./aicc");
const { querySambaNova }  = require("./sambanova");
const { queryMistral }    = require("./mistral");
const { queryNvidia }     = require("./nvidia");
const { queryOpenRouter } = require("./openrouter");
const { queryHuggingFace }= require("./huggingface");
const { queryBytez }      = require("./bytez");
const logger = require("../utils/logger");

const TIMEOUT_MS = 60000;

// Priority order — fastest/best first
const providerFn = {
  groq:        queryGroq,
  cerebras:    queryCerebras,
  aicc:        queryAiCC,
  sambanova:   querySambaNova,
  mistral:     queryMistral,
  nvidia:      queryNvidia,
  openrouter:  queryOpenRouter,
  huggingface: queryHuggingFace,
  bytez:       queryBytez,
};

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), ms)
    ),
  ]);
}

async function tryProvider(provider, prompt) {
  const providerModels = models[provider];
  if (!providerModels || providerModels.length === 0) {
    throw new Error(`No models for ${provider}`);
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
      const response = await withTimeout(
        providerFn[provider](model, prompt, apiKey),
        TIMEOUT_MS
      );

      if (!isValidResponse(response)) {
        logger.warn(`[${provider}/${name}] invalid response, skipping`);
        continue;
      }

      return { response, provider, model: name };
    } catch (err) {
      logger.warn(`[${provider}/${name}] failed: ${err.message}`);
    }
  }

  throw new Error(`All models failed for: ${provider}`);
}

async function getAIResponse(prompt) {
  const start = Date.now();

  const races = Object.keys(providerFn).map((p) => tryProvider(p, prompt));

  try {
    const result = await Promise.any(races);
    const time = ((Date.now() - start) / 1000).toFixed(2) + "s";
    logger.info(`✓ [${result.provider}/${result.model}] in ${time}`);
    return { ...result, time };
  } catch {
    throw new Error("All AI providers failed");
  }
}

module.exports = { getAIResponse };
