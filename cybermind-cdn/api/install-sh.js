// Serves install.sh — always latest from GitHub
const https = require("https");

const INSTALL_SH_URL =
  "https://raw.githubusercontent.com/thecnical/cybermind/main/install.sh";

module.exports = (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

  https.get(INSTALL_SH_URL, (ghRes) => {
    if (ghRes.statusCode !== 200) {
      res.status(502).send(`# GitHub returned ${ghRes.statusCode}`);
      return;
    }
    ghRes.pipe(res);
  }).on("error", (e) => {
    res.status(502).send("# Proxy error: " + e.message);
  });
};
