const logger = require("./logger");

/**
 * Log an incoming request with IP, endpoint, and status.
 * @param {object} req - Express request
 * @param {string} status - "success" | "fail" | "blocked"
 */
function logRequest(req, status = "success") {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const timestamp = new Date().toISOString();
  const endpoint = `${req.method} ${req.originalUrl}`;
  // Never log body contents to avoid leaking prompts or keys
  logger.info(`[${timestamp}] ${ip} ${endpoint} → ${status}`);
}

module.exports = { logRequest };
