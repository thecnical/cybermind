/**
 * Validate an AI response is useful and not garbage.
 * @param {string} response
 * @returns {boolean}
 */
function isValidResponse(response) {
  if (!response || typeof response !== "string") return false;
  const trimmed = response.trim();
  if (trimmed.length < 5) return false;

  // Only reject definitive loading/null states
  const errorPatterns = [
    /^model is currently loading$/i,
    /^\s*null\s*$/i,
    /^\s*undefined\s*$/i,
  ];

  return !errorPatterns.some((p) => p.test(trimmed));
}

module.exports = { isValidResponse };
