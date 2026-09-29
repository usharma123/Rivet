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
const probeUid = process.getuid?.() === 0 ? 2000 : undefined;
const probeGid = process.getuid?.() === 0 ? 2000 : undefined;
const auditNonce = process.env.RIVET_AUDIT_NONCE || "";

const HONEY_ENV = {
  NPM_TOKEN: "npm_RIVETHONEYTOKEN0000000000000000000000",
  NODE_AUTH_TOKEN: "npm_RIVETHONEYTOKEN0000000000000000000001",
  GITHUB_TOKEN: "ghp_RIVETHONEYTOKEN000000000000000000000000",
  AWS_ACCESS_KEY_ID: "AKIARIVETHONEYTOKEN0",
  AWS_SECRET_ACCESS_KEY: "rivet/honeytoken/secret/access/key/000000",
};

function main() {
  if (auditNonce && probeUid !== undefined) {
    const evidenceStat = fs.statSync(evidenceDir);
    if (evidenceStat.uid === probeUid || (evidenceStat.mode & 0o077) !== 0) {
      throw new Error("evidence directory is accessible to the package probe UID or group");
    }
  }
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(workDir, { recursive: true });
  const egressLog = path.join(workDir, "egress.jsonl");
  fs.writeFileSync(egressLog, "");
  if (probeUid !== undefined) fs.chownSync(egressLog, probeUid, probeGid);
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
    if (probeUid !== undefined) makeProbeOwned(packageDir);
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
  const packageJson = readJson(path.join(packageDir, "package.json"));

  const env = {
    // Use the supervisor's trusted Node installation for lifecycle scripts too.
    // Hosted runners may install it outside the system PATH directories.
    PATH: `${path.dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`,
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
  const required = [];
  for (const name of ["preinstall", "install", "postinstall"]) {
    if (typeof scripts[name] !== "string" || !scripts[name]) continue;
    const result = run("script:" + name, "sh", ["-c", scripts[name]], packageDir, { ...env, npm_lifecycle_event: name }, adversarialTimeout);
    evidence.adversarial_probes.push(result);
    required.push({ name: result.name, passed: result.exit_code === 0 && !result.timeout });
  }
  const requireProbe = run("require", process.execPath, ["-e", "require(process.argv[1])", packageDir], workDir, env, safeTimeout);
  evidence.adversarial_probes.push(requireProbe);
  for (const field of ["main", "module"]) {
    if (typeof packageJson[field] !== "string" || !packageJson[field]) continue;
    const full = packageEntry(packageDir, packageJson[field]);
    const result = full
      ? run(`entry:${field}`, process.execPath, ["-e", "import(require('node:url').pathToFileURL(process.argv[1]).href)", full], packageDir, env, safeTimeout)
      : probeResult(`entry:${field}`, String(packageJson[field]), { status: 1, stderr: "entry escapes the canonical package" });
    evidence.adversarial_probes.push(result);
    required.push({ name: result.name, passed: result.exit_code === 0 && !result.timeout });
  }
  for (const [command, entry] of Object.entries(binEntries(manifest))) {
    const full = packageEntry(packageDir, String(entry));
    if (!full) {
      required.push({ name: `bin:${command}`, passed: false });
      evidence.safe_probes.push(probeResult(`bin:${command}`, String(entry), { status: 1, stderr: "bin escapes the canonical package" }));
      continue;
    }
    let invocation;
    try { invocation = binInvocation(full); }
    catch (error) {
      required.push({ name: `bin:${command}`, passed: false });
      evidence.safe_probes.push(probeResult(`bin:${command}`, full, { status: 1, error }));
      continue;
    }
    const results = [];
    for (const flag of ["--version", "--help"]) {
      const result = run(`${flag.slice(2)}:${command}`, invocation.command, [...invocation.args, flag], packageDir, env, safeTimeout);
      evidence.safe_probes.push(result);
      results.push(result);
    }
    required.push({ name: `bin:${command}`, passed: results.some((result) => result.exit_code === 0 && !result.timeout) });
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
    }
  }
  evidence.egress = dedupe(evidence.egress, (e) => `${e.probe}|${e.host}|${e.port}|${e.protocol}`).slice(0, 50);
  evidence.honeytokens = dedupe(evidence.honeytokens, (h) => `${h.probe}|${h.token}`).slice(0, 50);
  const probes = [...evidence.safe_probes, ...evidence.adversarial_probes];
  const runnable = required.length
    ? required.every((target) => target.passed)
    : requireProbe.exit_code === 0 && !requireProbe.timeout;
  const timedOut = probes.some((probe) => probe.timeout);
  if (probeUid !== undefined) stopPackageProcesses();
  evidence.agent.complete = runnable && !timedOut ? "true" : "false";
  evidence.agent.required_targets = String(required.length);
  const failedTarget = required.find((target) => !target.passed);
  if (failedTarget) evidence.agent.failed_target = failedTarget.name.slice(0, 100);
  writeEvidence(evidence);
  // The trace collector accepts this syscall only from the root supervisor.
  // Package probes run as another UID and do not receive the nonce. The path
  // deliberately does not exist; openat/enter records the attempted open.
  if (auditNonce && evidence.agent.complete === "true") {
    try { fs.openSync(`/rivet-audit-complete-${auditNonce}`, "r"); } catch {}
    fs.writeFileSync(path.join(evidenceDir, "ready"), auditNonce, { flag: "wx" });
    const releasePath = path.join(evidenceDir, "release");
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      try {
        if (fs.readFileSync(releasePath, "utf8") === auditNonce) return;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
    }
    throw new Error("host audit supervisor did not release completed probe");
  }
  if (evidence.agent.complete !== "true") process.exitCode = 1;
}

function makeProbeOwned(root) {
  const walk = (file) => {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink()) throw new Error("canonical package contains a symlink");
    fs.chownSync(file, probeUid, probeGid);
    if (stat.isDirectory()) for (const name of fs.readdirSync(file)) walk(path.join(file, name));
  };
  walk(root);
}

function stopPackageProcesses() {
  // PID 1 remains alive while we reap detached descendants. Package code
  // cannot change UID after setpriv has dropped its groups and capabilities.
  for (let pass = 0; pass < 3; pass++) {
    let found = 0;
    for (const name of fs.readdirSync("/proc")) {
      if (!/^\d+$/.test(name)) continue;
      let status;
      try { status = fs.readFileSync(`/proc/${name}/status`, "utf8"); } catch (error) {
        if (error.code === "ENOENT") continue;
        throw error;
      }
      const uidLine = status.match(/^Uid:\s+(\d+)\s+(\d+)/m);
      if (!uidLine || (Number(uidLine[1]) !== probeUid && Number(uidLine[2]) !== probeUid)) continue;
      if (/^State:\s+Z/m.test(status)) continue;
      found++;
      try { process.kill(Number(name), "SIGKILL"); } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    }
    if (!found) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  }
  throw new Error("package child processes remained after probe cleanup");
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
  fs.mkdirSync(dir, { recursive: true });
  // The sticky bit lets the package write ordinary HOME files but prevents
  // it from renaming the root-owned credential files to an untraced alias.
  fs.chmodSync(dir, 0o1777);
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(dir, relative);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, { mode: 0o444 });
    fs.chmodSync(full, 0o444);
    paths.push(full);
  }
  paths.push(path.join(dir, ".ssh"), path.join(dir, ".aws"));
  return { dir, paths };
}

function run(name, command, args, cwd, env, timeout) {
  const probeCommand = probeUid === undefined ? command : "/bin/setpriv";
  const probeArgs = probeUid === undefined ? args : ["--reuid=2000", "--regid=2000", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", command, ...args];
  const result = spawnSync(probeCommand, probeArgs, { cwd, env: { ...env, RIVET_PROBE_NAME: name }, encoding: "utf8", timeout, maxBuffer: 256 * 1024 });
  return probeResult(name, [path.basename(command), ...args].join(" "), result);
}

function probeResult(name, command, result) {
  const error = result.error ? String(result.error.message || result.error) : "";
  return {
    name,
    command: command.slice(0, 400),
    exit_code: result.status ?? 1,
    timeout: result.error?.code === "ETIMEDOUT",
    output: redact(`${result.stdout || ""}\n${result.stderr || ""}\n${error}`).slice(0, 2048),
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

function packageEntry(packageDir, entry) {
  const full = path.resolve(packageDir, entry);
  return full.startsWith(packageDir + path.sep) ? full : null;
}

function binInvocation(file) {
  const fd = fs.openSync(file, "r");
  const head = Buffer.alloc(256);
  let length;
  try { length = fs.readSync(fd, head, 0, head.length, 0); }
  finally { fs.closeSync(fd); }
  const bytes = head.subarray(0, length);
  const newline = bytes.indexOf(10);
  const first = bytes.subarray(0, newline < 0 ? bytes.length : newline);
  const shebang = first.subarray(0, 2).toString() === "#!";
  const nodeShebang = shebang && first.toString("utf8").includes("node");
  const native = bytes.subarray(0, 4).equals(Buffer.from([0x7f, 69, 76, 70]))
    || bytes.subarray(0, 4).equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))
    || bytes.subarray(0, 4).equals(Buffer.from([0xca, 0xfe, 0xba, 0xbe]));
  if ([".js", ".cjs", ".mjs"].includes(path.extname(file)) || nodeShebang || (!native && !shebang)) {
    return { command: process.execPath, args: [file] };
  }
  return { command: file, args: [] };
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
