#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const artifactPath = "/artifact/package.tgz";
const workDir = "/tmp/rivet-audit";
let packageDir = path.join(workDir, "package");
const evidencePath = "/evidence/evidence.json";

async function main() {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(workDir, { recursive: true });
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });

  const extract = spawnSync("tar", ["-xzf", artifactPath, "-C", workDir], {
    encoding: "utf8",
    timeout: 30000,
  });
  const evidence = {
    static: {
      artifact_size: fileSize(artifactPath),
      has_install_scripts: false,
      install_scripts: [],
      has_native_binaries: false,
      native_binaries: [],
      minified_files: [],
      obfuscated_files: [],
      source_visibility: "unknown",
      source_repo: "",
      namesquat_warning: "",
    },
    safe_probes: [],
    adversarial_probes: [],
    egress: [],
    privacy: {
      will_send: [
        "package manifest",
        "dependency summary",
        "executable metadata",
        "install scripts",
        "release diff",
        "selected suspicious snippets",
      ],
      will_not_send: [
        ".env files",
        "registry tokens",
        "git credentials",
        "private project files",
        "shell history",
      ],
    },
    sandbox: {
      runtime: "gvisor/runsc",
      network: "rivet-audit-net",
      direct_internet: "denied_by_policy",
    },
    agent: {
      name: "rivet-audit-agent",
      version: "0.1.0",
    },
  };

  if (extract.status !== 0) {
    evidence.safe_probes.push({
      name: "extract",
      command: "tar -xzf package.tgz",
      exit_code: extract.status ?? 1,
      timeout: false,
      output: redact(`${extract.stdout}\n${extract.stderr}`),
    });
    writeEvidence(evidence);
    return;
  }
  if (!fs.existsSync(packageDir)) {
    packageDir = workDir;
  }

  const manifest = readJson(path.join(packageDir, "package.json"));
  scanStatic(packageDir, manifest, evidence);
  runSafeProbes(packageDir, manifest, evidence);
  runAdversarialProbes(packageDir, manifest, evidence);
  await callAuditProxy(evidence);
  writeEvidence(evidence);
}

function scanStatic(root, manifest, evidence) {
  const scripts = manifest.scripts || {};
  for (const name of ["preinstall", "install", "postinstall"]) {
    if (scripts[name]) {
      evidence.static.install_scripts.push(name);
    }
  }
  evidence.static.has_install_scripts = evidence.static.install_scripts.length > 0;
  evidence.static.source_repo = sourceRepo(manifest);
  evidence.static.source_visibility = evidence.static.source_repo ? "open" : "unknown";

  for (const file of walk(root)) {
    const rel = path.relative(root, file);
    if (/\.(node|dll|dylib|so|exe)$/i.test(rel)) {
      evidence.static.native_binaries.push(rel);
    }
    if (/\.(js|cjs|mjs)$/i.test(rel)) {
      const text = fs.readFileSync(file, "utf8").slice(0, 256000);
      if (looksMinified(text)) evidence.static.minified_files.push(rel);
      if (looksObfuscated(text)) evidence.static.obfuscated_files.push(rel);
    }
  }
  evidence.static.has_native_binaries = evidence.static.native_binaries.length > 0;
}

function runSafeProbes(root, manifest, evidence) {
  const bins = binEntries(manifest);
  for (const [command, entry] of Object.entries(bins)) {
    const full = path.join(root, entry.replace(/^\.\//, ""));
    evidence.safe_probes.push(runProbe("version:" + command, full, ["--version"], 30000));
    evidence.safe_probes.push(runProbe("help:" + command, full, ["--help"], 30000));
  }
}

function runAdversarialProbes(root, manifest, evidence) {
  const scripts = manifest.scripts || {};
  for (const name of ["preinstall", "install", "postinstall"]) {
    if (!scripts[name]) continue;
    evidence.adversarial_probes.push(
      runProbe("script:" + name, "npm", ["run", name, "--ignore-scripts"], 120000, root),
    );
  }
}

function runProbe(name, executable, args, timeout, cwd = packageDir) {
  const command = /\.[cm]?js$/i.test(executable) ? "node" : executable;
  const finalArgs = command === "node" ? [executable, ...args] : args;
  const result = spawnSync(command, finalArgs, {
    cwd,
    encoding: "utf8",
    timeout,
    maxBuffer: 128 * 1024,
  });
  return {
    name,
    command: [command, ...finalArgs].join(" "),
    exit_code: result.status ?? (result.error ? 1 : 0),
    timeout: result.error?.code === "ETIMEDOUT",
    output: redact(`${result.stdout || ""}\n${result.stderr || ""}`).slice(0, 4096),
  };
}

async function callAuditProxy(evidence) {
  const url = process.env.RIVET_AUDIT_PROXY_URL;
  const token = process.env.RIVET_AUDIT_TOKEN;
  if (!url || !token || typeof fetch !== "function") return;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-rivet-audit-token": token,
      },
      body: JSON.stringify({
        package: process.env.RIVET_PACKAGE_NAME,
        version: process.env.RIVET_PACKAGE_VERSION,
        evidence,
      }),
    });
    evidence.agent.proxy_status = String(response.status);
  } catch (error) {
    evidence.egress.push({
      host: "audit-proxy",
      port: 443,
      protocol: "https",
      bytes: 0,
      decision: "blocked",
    });
    evidence.agent.proxy_error = redact(String(error.message || error));
  }
}

function writeEvidence(evidence) {
  fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2));
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return {};
  }
}

function binEntries(manifest) {
  if (!manifest.bin) return {};
  if (typeof manifest.bin === "string") {
    return { [manifest.name || "package"]: manifest.bin };
  }
  return manifest.bin;
}

function sourceRepo(manifest) {
  const repo = manifest.repository;
  if (typeof repo === "string") return repo;
  if (repo && typeof repo.url === "string") return repo.url;
  return "";
}

function walk(root) {
  const out = [];
  for (const name of fs.readdirSync(root)) {
    const file = path.join(root, name);
    const stat = fs.statSync(file);
    if (stat.isDirectory()) out.push(...walk(file));
    else out.push(file);
  }
  return out;
}

function looksMinified(text) {
  const lines = text.split(/\r?\n/);
  const longLines = lines.filter((line) => line.length > 500).length;
  return longLines >= 3 || text.length > 10000 && lines.length < 20;
}

function looksObfuscated(text) {
  return /eval\s*\(|Function\s*\(|atob\s*\(|\\x[0-9a-fA-F]{2}/.test(text);
}

function fileSize(file) {
  try {
    return fs.statSync(file).size;
  } catch {
    return 0;
  }
}

function redact(text) {
  return text
    .replace(/(RIVET_REGISTRY_TOKEN|RIVET_AUDIT_TOKEN|API_KEY)=\S+/g, "$1=[REDACTED]")
    .replace(/sk-[A-Za-z0-9_-]{10,}/g, "sk-[REDACTED]");
}

main().catch((error) => {
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(
    evidencePath,
    JSON.stringify(
      {
        static: {
          artifact_size: fileSize(artifactPath),
          has_install_scripts: false,
          has_native_binaries: false,
          source_visibility: "unknown",
        },
        safe_probes: [
          {
            name: "agent",
            exit_code: 1,
            timeout: false,
            output: redact(String(error && error.stack ? error.stack : error)),
          },
        ],
      },
      null,
      2,
    ),
  );
  process.exitCode = 1;
});
