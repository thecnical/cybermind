const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
require("dotenv").config();

const chatRoutes    = require("./routes/chat");
const toolsRoutes   = require("./routes/tools");
const scanRoutes    = require("./routes/scan");
const exploitRoutes = require("./routes/exploit");
const reconRoutes   = require("./routes/recon");
const rateLimiter   = require("./middleware/rateLimiter");

const app = express();

app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.use(morgan("dev"));

// Health check
app.get("/", (req, res) => {
  res.json({
    status: "CyberMind backend running",
    version: "2.0.0",
    routes: ["/chat", "/tools", "/scan", "/exploit", "/recon"],
  });
});

// Routes — all rate limited
app.use("/chat",    rateLimiter, chatRoutes);
app.use("/tools",   rateLimiter, toolsRoutes);
app.use("/scan",    rateLimiter, scanRoutes);
app.use("/exploit", rateLimiter, exploitRoutes);
app.use("/recon",   rateLimiter, reconRoutes);

// Global error handler
app.use((err, req, res, next) => {
  console.error("[UNHANDLED]", err.message);
  res.status(500).json({ success: false, error: "Server error. Try again later." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚡ CyberMind backend v2.0.0 running on port ${PORT}`);
  console.log(`   Routes: /chat /tools /scan /exploit /recon`);
});

module.exports = app;
