// Proxies binary downloads from GitHub raw — always latest
const https = require("https");

const GITHUB_RAW =
  "https://raw.githubusercontent.com/thecnical/cybermind/main/cli/";

const ALLOWED = new Set([
  "cybermind-linux-amd64",
  "cybermind-linux-arm64",
  "cybermind-darwin-amd64",
  "cybermind-darwin-arm64",
  "cybermind-windows-amd64.exe",
]);

module.exports = (req, res) => {
  const file = req.query.file;
  if (!file || !ALLOWED.has(file)) {
    res.status(400).send("Invalid file");
    return;
  }

  const url = GITHUB_RAW + file;
  const isExe = file.endsWith(".exe");

  res.setHeader("Content-Type", isExe ? "application/octet-stream" : "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${file}"`);
  res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

  https.get(url, (ghRes) => {
    if (ghRes.statusCode === 302 || ghRes.statusCode === 301) {
      // Follow redirect
      https.get(ghRes.headers.location, (r2) => r2.pipe(res));
      return;
    }
    if (ghRes.statusCode !== 200) {
      res.status(502).send(`GitHub returned ${ghRes.statusCode}`);
      return;
    }
    ghRes.pipe(res);
  }).on("error", (e) => {
    res.status(502).send("Proxy error: " + e.message);
  });
};
