const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
require("dotenv").config();

const chatRoutes = require("./routes/chat");
const rateLimiter = require("./middleware/rateLimiter");

const app = express();

// Global middleware
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// Health check
app.get("/", (req, res) => {
  res.json({ status: "CyberMind backend running" });
});

// Rate limiter applied to /chat only
app.use("/chat", rateLimiter, chatRoutes);

// Global error handler — never expose internals
app.use((err, req, res, next) => {
  console.error("[UNHANDLED]", err.message);
  res.status(500).json({ success: false, error: "Server error. Try again later." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CyberMind backend running on port ${PORT}`);
});

module.exports = app;
