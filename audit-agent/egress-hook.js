// Preloaded into every Node process the audit agent starts (NODE_OPTIONS
// --require). It records network, DNS, child-process and honeytoken access
// before the call reaches the (network-less) sandbox. Native code and
// non-Node processes are not observed by this hook; gVisor's lack of any
// network namespace is what actually stops egress.
"use strict";

const fs = require("node:fs");
const net = require("node:net");
const dns = require("node:dns");
const dgram = require("node:dgram");
const childProcess = require("node:child_process");

const logPath = process.env.RIVET_EGRESS_LOG;
const probe = process.env.RIVET_PROBE_NAME || "unknown";
const honeyPaths = (process.env.RIVET_HONEYTOKEN_PATHS || "").split(":").filter(Boolean);
const honeyEnv = (process.env.RIVET_HONEYTOKEN_ENV || "").split(",").filter(Boolean);
const appendFileSync = fs.appendFileSync;

function record(entry) {
  if (!logPath) return;
  try {
    appendFileSync(logPath, JSON.stringify({ probe, ...entry }) + "\n");
  } catch {
    // never let instrumentation change package behaviour
  }
}

function checkPath(target, how) {
  if (typeof target !== "string" && !(target instanceof URL) && !Buffer.isBuffer(target)) return;
  const value = String(target instanceof URL ? target.pathname : target);
  for (const honey of honeyPaths) {
    if (value === honey || value.startsWith(honey + "/")) {
      record({ kind: "honeytoken", token: honey, how });
    }
  }
}

for (const name of ["readFileSync", "readFile", "openSync", "open", "createReadStream", "readdirSync", "readdir", "existsSync", "statSync"]) {
  const original = fs[name];
  if (typeof original !== "function") continue;
  fs[name] = function patched(target, ...rest) {
    checkPath(target, "fs." + name);
    return original.call(this, target, ...rest);
  };
}
if (fs.promises) {
  for (const name of ["readFile", "open", "readdir"]) {
    const original = fs.promises[name];
    if (typeof original !== "function") continue;
    fs.promises[name] = function patched(target, ...rest) {
      checkPath(target, "fs.promises." + name);
      return original.call(this, target, ...rest);
    };
  }
}

const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function patchedConnect(...args) {
  let host = "";
  let port = 0;
  const first = args[0];
  if (first && typeof first === "object" && !Array.isArray(first)) {
    host = first.host || first.path || "";
    port = Number(first.port || 0);
  } else if (typeof first === "number" || /^\d+$/.test(String(first))) {
    port = Number(first);
    host = typeof args[1] === "string" ? args[1] : "localhost";
  } else if (typeof first === "string") {
    host = first;
  }
  record({ kind: "egress", host, port, protocol: "tcp" });
  return connect.apply(this, args);
};

for (const name of ["lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveAny"]) {
  const original = dns[name];
  if (typeof original !== "function") continue;
  dns[name] = function patched(hostname, ...rest) {
    record({ kind: "egress", host: String(hostname), port: 53, protocol: "dns" });
    return original.call(this, hostname, ...rest);
  };
}

const send = dgram.Socket.prototype.send;
dgram.Socket.prototype.send = function patchedSend(...args) {
  const port = args.find((value) => typeof value === "number" && value > 0) || 0;
  const host = args.find((value) => typeof value === "string") || "";
  record({ kind: "egress", host, port, protocol: "udp" });
  return send.apply(this, args);
};

if (typeof globalThis.fetch === "function") {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = function patchedFetch(input, init) {
    try {
      const target = new URL(typeof input === "string" ? input : input.url);
      record({ kind: "egress", host: target.hostname, port: Number(target.port || (target.protocol === "https:" ? 443 : 80)), protocol: target.protocol.replace(":", "") });
    } catch {
      record({ kind: "egress", host: "unparseable-fetch", port: 0, protocol: "http" });
    }
    return originalFetch.call(this, input, init);
  };
}

for (const name of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  const original = childProcess[name];
  if (typeof original !== "function") continue;
  childProcess[name] = function patched(command, ...rest) {
    const args = Array.isArray(rest[0]) ? rest[0].join(" ") : "";
    record({ kind: "process", command: String(command).slice(0, 200) + (args ? " " + args.slice(0, 200) : "") });
    return original.call(this, command, ...rest);
  };
}

if (honeyEnv.length > 0) {
  const env = process.env;
  process.env = new Proxy(env, {
    get(target, key) {
      if (typeof key === "string" && honeyEnv.includes(key)) {
        record({ kind: "honeytoken", token: "env:" + key, how: "process.env" });
      }
      return Reflect.get(target, key);
    },
    ownKeys(target) {
      record({ kind: "env_enumeration" });
      return Reflect.ownKeys(target);
    },
  });
}
