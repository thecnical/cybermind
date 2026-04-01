const express = require("express");
const router = express.Router();

// Placeholder for AI chat integration
router.post("/", (req, res) => {
  const { prompt } = req.body;
  // TODO: integrate AI service in Phase 1
  res.json({ message: "Chat endpoint ready", prompt });
});

module.exports = router;
