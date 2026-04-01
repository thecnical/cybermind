const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
require("dotenv").config();

const chatRoutes = require("./routes/chat");

const app = express();

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

app.get("/", (req, res) => {
  res.json({ status: "CyberMind backend running" });
});

app.use("/chat", chatRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CyberMind backend running on port ${PORT}`);
});

module.exports = app;
