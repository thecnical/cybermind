const logger = require("../utils/logger");

const WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS = 20;

// ip → { count, resetAt }
const store = new Map();

// Clean up expired entries every minute to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of store.entries()) {
    if (now >= data.resetAt) store.delete(ip);
  }
}, WINDOW_MS);

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const now = Date.now();

  const record = store.get(ip);

  if (!record || now >= record.resetAt) {
    store.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }

  record.count++;

  if (record.count > MAX_REQUESTS) {
    logger.warn(`Rate limit exceeded for IP: ${ip}`);
    return res.status(429).json({
      success: false,
      error: "Too many requests. Please try again later.",
    });
  }

  next();
}

module.exports = rateLimiter;
