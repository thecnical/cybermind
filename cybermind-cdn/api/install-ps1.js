// Serves install.ps1 — always latest from GitHub
const https = require("https");

const INSTALL_PS1_URL =
  "https://raw.githubusercontent.com/thecnical/cybermind/main/install.ps1";

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

  https.get(INSTALL_PS1_URL, (ghRes) => {
    if (ghRes.statusCode !== 200) {
      res.status(502).send(`# GitHub returned ${ghRes.statusCode}`);
      return;
    }
    ghRes.pipe(res);
  }).on("error", (e) => {
    res.status(502).send("# Proxy error: " + e.message);
  });
};
