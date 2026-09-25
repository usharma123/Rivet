#!/usr/bin/env node
// Rivet dynamic audit agent. Runs inside gVisor with --network=none and a
// read-only root. It executes the package's install scripts, loads its entry
// point, and runs its executables with honeytoken credentials planted, then
// writes what it observed to evidence.json. Static analysis is done by the
// registry itself and is not repeated here.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const artifactPath = process.env.RIVET_ARTIFACT_PATH || "/artifact/package.tgz";
const canonicalPackage = process.env.RIVET_CANONICAL_PACKAGE_DIR || "/artifact/package";
const manifestPath = process.env.RIVET_MANIFEST_PATH || "/audit/manifest.json";
const evidenceDir = process.env.RIVET_EVIDENCE_DIR || "/evidence";
const workDir = process.env.RIVET_WORK_DIR || path.join(os.tmpdir(), "rivet-work");
const hookPath = path.join(__dirname, "egress-hook.js");
const safeTimeout = Number(process.env.RIVET_SAFE_TIMEOUT_MS || 30000);
const adversarialTimeout = Number(process.env.RIVET_ADVERSARIAL_TIMEOUT_MS || 120000);

const HONEY_ENV = {
  NPM_TOKEN: "npm_RIVETHONEYTOKEN0000000000000000000000",
  NODE_AUTH_TOKEN: "npm_RIVETHONEYTOKEN0000000000000000000001",
  GITHUB_TOKEN: "ghp_RIVETHONEYTOKEN000000000000000000000000",
  AWS_ACCESS_KEY_ID: "AKIARIVETHONEYTOKEN0",
  AWS_SECRET_ACCESS_KEY: "rivet/honeytoken/secret/access/key/000000",
};

function main() {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(workDir, { recursive: true });
  const egressLog = path.join(workDir, "egress.jsonl");
  const home = plantHoneytokens(path.join(workDir, "home"));

  const evidence = {
    safe_probes: [],
    adversarial_probes: [],
    egress: [],
    honeytokens: [],
    agent: { name: "rivet-audit-agent", version: "2", node: process.version },
  };

  let packageDir;
  let manifest;
  if (fs.existsSync(canonicalPackage)) {
    packageDir = path.join(workDir, "package");
    fs.cpSync(canonicalPackage, packageDir, { recursive: true });
    manifest = readJson(manifestPath);
    if (!manifest.name || !manifest.version) throw new Error("authoritative audit manifest is missing");
  } else {
    // Local agent fixtures retain the raw-tar entry point. DockerRunner always
    // mounts the registry's canonical tree and normalized manifest.
    const extract = spawnSync("tar", ["-xzf", artifactPath, "-C", workDir, "--no-same-owner", "--no-same-permissions"], {
      encoding: "utf8",
      timeout: 30000,
    });
    if (extract.status !== 0) {
      evidence.safe_probes.push(probeResult("extract", "tar -xzf package.tgz", extract));
      throw new Error("raw fixture extraction failed");
    }
    packageDir = findPackageDir(workDir);
    manifest = readJson(path.join(packageDir, "package.json"));
  }

  const env = {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: home.dir,
    CI: "true",
    GITHUB_ACTIONS: "true",
    npm_lifecycle_event: "",
    NODE_OPTIONS: `--require ${hookPath}`,
    RIVET_EGRESS_LOG: egressLog,
    RIVET_HONEYTOKEN_PATHS: home.paths.join(":"),
    RIVET_HONEYTOKEN_ENV: Object.keys(HONEY_ENV).join(","),
    ...HONEY_ENV,
  };

  const scripts = manifest.install_scripts || manifest.scripts || {};
  for (const name of ["preinstall", "install", "postinstall"]) {
    if (typeof scripts[name] !== "string" || !scripts[name]) continue;
    const result = run("script:" + name, "sh", ["-c", scripts[name]], packageDir, { ...env, npm_lifecycle_event: name }, adversarialTimeout);
    evidence.adversarial_probes.push(result);
  }
  const requireProbe = run("require", process.execPath, ["-e", "require(process.argv[1])", packageDir], workDir, env, safeTimeout);
  evidence.adversarial_probes.push(requireProbe);
  for (const [command, entry] of Object.entries(binEntries(manifest))) {
    const full = path.join(packageDir, String(entry).replace(/^\.\//, ""));
    if (!full.startsWith(packageDir + path.sep)) continue;
    for (const flag of ["--version", "--help"]) {
      evidence.safe_probes.push(run(`${flag.slice(2)}:${command}`, process.execPath, [full, flag], packageDir, env, safeTimeout));
    }
  }

  for (const entry of readJsonLines(egressLog)) {
    if (entry.kind === "egress") {
      evidence.egress.push({
        host: String(entry.host || "").slice(0, 255),
        port: Number(entry.port || 0),
        protocol: String(entry.protocol || ""),
        bytes: 0,
        decision: "blocked",
        probe: entry.probe,
      });
    } else if (entry.kind === "honeytoken") {
      evidence.honeytokens.push({ token: String(entry.token), probe: entry.probe, how: entry.how });
    } else if (entry.kind === "process") {
      evidence.adversarial_probes.push({ name: "spawned:" + entry.probe, command: String(entry.command).slice(0, 400), exit_code: 0, timeout: false });
    }
  }
  evidence.egress = dedupe(evidence.egress, (e) => `${e.probe}|${e.host}|${e.port}|${e.protocol}`).slice(0, 50);
  evidence.honeytokens = dedupe(evidence.honeytokens, (h) => `${h.probe}|${h.token}`).slice(0, 50);
  const hasTarget = Object.keys(scripts).some((name) => ["preinstall", "install", "postinstall"].includes(name)) || Object.keys(binEntries(manifest)).length > 0 || requireProbe.exit_code === 0;
  evidence.agent.complete = hasTarget ? "true" : "false";
  writeEvidence(evidence);
}

function plantHoneytokens(dir) {
  const files = {
    ".npmrc": `//registry.npmjs.org/:_authToken=${HONEY_ENV.NPM_TOKEN}\n`,
    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nrivet-honeytoken\n-----END OPENSSH PRIVATE KEY-----\n",
    ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nrivet-honeytoken\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": `[default]\naws_access_key_id = ${HONEY_ENV.AWS_ACCESS_KEY_ID}\naws_secret_access_key = ${HONEY_ENV.AWS_SECRET_ACCESS_KEY}\n`,
    ".config/gh/hosts.yml": `github.com:\n  oauth_token: ${HONEY_ENV.GITHUB_TOKEN}\n`,
    ".git-credentials": `https://rivet:${HONEY_ENV.GITHUB_TOKEN}@github.com\n`,
    ".docker/config.json": '{"auths":{"https://index.docker.io/v1/":{"auth":"cml2ZXQ6aG9uZXl0b2tlbg=="}}}\n',
  };
  const paths = [];
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(dir, relative);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, { mode: 0o600 });
    paths.push(full);
  }
  paths.push(path.join(dir, ".ssh"), path.join(dir, ".aws"));
  return { dir, paths };
}

function run(name, command, args, cwd, env, timeout) {
  const result = spawnSync(command, args, { cwd, env: { ...env, RIVET_PROBE_NAME: name }, encoding: "utf8", timeout, maxBuffer: 256 * 1024 });
  return probeResult(name, [path.basename(command), ...args].join(" "), result);
}

function probeResult(name, command, result) {
  return {
    name,
    command: command.slice(0, 400),
    exit_code: result.status ?? 1,
    timeout: result.error?.code === "ETIMEDOUT",
    output: redact(`${result.stdout || ""}\n${result.stderr || ""}`).slice(0, 2048),
  };
}

function findPackageDir(root) {
  const entries = fs.readdirSync(root).filter((name) => name !== "home" && name !== "egress.jsonl");
  if (entries.length === 1 && fs.statSync(path.join(root, entries[0])).isDirectory()) {
    return path.join(root, entries[0]);
  }
  return root;
}

function binEntries(manifest) {
  if (!manifest.bin) return {};
  if (typeof manifest.bin === "string") {
    return { [String(manifest.name || "package").split("/").pop()]: manifest.bin };
  }
  return manifest.bin;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return {};
  }
}

function readJsonLines(file) {
  try {
    return fs
      .readFileSync(file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function dedupe(items, key) {
  const seen = new Set();
  return items.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function redact(text) {
  let out = text;
  for (const value of Object.values(HONEY_ENV)) out = out.split(value).join("[HONEYTOKEN]");
  return out.replace(/(RIVET_REGISTRY_TOKEN|API_KEY)=\S+/g, "$1=[REDACTED]");
}

function writeEvidence(evidence) {
  fs.mkdirSync(evidenceDir, { recursive: true });
  fs.writeFileSync(path.join(evidenceDir, "evidence.json"), JSON.stringify(evidence, null, 2));
}

try {
  main();
} catch (error) {
  writeEvidence({
    safe_probes: [{ name: "agent", exit_code: 1, timeout: false, output: redact(String(error && error.stack ? error.stack : error)) }],
  });
  process.exitCode = 1;
}
