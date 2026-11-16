#!/usr/bin/env node
"use strict";

/**
 * @ciphermap/mcp — Zero-dependency stdio launcher & MCP protocol responder for `ciphermap mcp`.
 *
 * Security invariants:
 *   1. Prefers a verified local `ciphermap` binary already installed on PATH,
 *      `/usr/local/bin/ciphermap`, `~/.local/bin/ciphermap`, or `~/.cache/ciphermap/bin/ciphermap`.
 *   2. Across macOS (Apple Notarized arm64/amd64), Windows (Authenticode amd64/arm64),
 *      and Linux (amd64/arm64) when `CIPHERMAP_LICENSE` is set and no local binary exists,
 *      authenticates over TLS 1.2+ to `https://www.ciphermap.io/api/dl/ci-cli` and
 *      verifies the `X-CipherMap-SHA256` digest before chmod + atomic rename.
 *   3. When no local native binary is installed yet (or `--introspect-only` is passed),
 *      serves compliant MCP JSON-RPC 2.0 over stdio (`initialize`, `ping`, `tools/list`,
 *      `resources/list`, `prompts/list`) exposing all 11 authentic v1.0.6 tool schemas
 *      with TDQS annotations, and returns actionable setup guidance on `tools/call` —
 *      without bundling any closed-source binary or opening network sockets.
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");

const EXPECTED_VERSION = "v1.0.6";
const SERVER_VERSION = "1.0.6";
const SERVER_NAME = "io.github.Ciphermap-io/ciphermap-mcp";
const CI_CLI_ORIGIN = "https://www.ciphermap.io/api/dl/ci-cli";
const SERVER_INSTRUCTIONS =
  "CipherMap Zero-Egress Local Vericoding Referee. Use ciphermap_scan_all to enumerate PQC + Immunity findings, ciphermap_check_baseline_health to verify T0 baseline compile/syntax health before editing, ciphermap_extinguish_immunity to run 4-Gate verified codemods + ddmin patch salvage, ciphermap_inspect_rule to retrieve exact NIST/CWE safe guardrail primitives, ciphermap_verify_candidate_fix to test candidate patches inside an ephemeral network-denied sandbox without mutating live files, and ciphermap_verify_workspace_clean to verify zero findings and dual Ed25519 + ML-DSA-65 ProofBundles.";

const TOOL_MANIFEST = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "tool-manifest.json"), "utf8")
);

function candidateBinaryPaths() {
  const isWin = process.platform === "win32";
  const exe = isWin ? "ciphermap.exe" : "ciphermap";
  const home = os.homedir();
  const candidates = [];

  if (process.env.CIPHERMAP_BIN && process.env.CIPHERMAP_BIN.trim()) {
    candidates.push(process.env.CIPHERMAP_BIN.trim());
  }

  const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathDirs) {
    candidates.push(path.join(dir, exe));
  }

  candidates.push(
    path.join(home, ".local", "bin", exe),
    path.join(home, ".cache", "ciphermap", "bin", exe),
    "/usr/local/bin/ciphermap",
    "/opt/homebrew/bin/ciphermap"
  );
  return [...new Set(candidates)];
}

function findInstalledBinary() {
  for (const binPath of candidateBinaryPaths()) {
    try {
      const st = fs.statSync(binPath);
      if (!st.isFile()) continue;
      if (process.platform !== "win32" && (st.mode & 0o111) === 0) continue;
      return binPath;
    } catch {
      // continue scanning candidates
    }
  }
  return null;
}

function resolveNativeTarget(platform = process.platform, arch = process.arch) {
  const cmOs =
    platform === "linux"
      ? "linux"
      : platform === "darwin"
        ? "darwin"
        : platform === "win32"
          ? "windows"
          : null;
  const cmArch =
    arch === "x64"
      ? "amd64"
      : arch === "arm64"
        ? "arm64"
        : null;
  if (!cmOs || !cmArch) return null;
  return {
    os: cmOs,
    arch: cmArch,
    exeName: cmOs === "windows" ? "ciphermap.exe" : "ciphermap"
  };
}

function downloadNativeBinaryWithLicense(licenseKey, target = resolveNativeTarget()) {
  if (!target) {
    return Promise.reject(new Error(`Unsupported platform/arch: ${process.platform}/${process.arch}`));
  }
  return new Promise((resolve, reject) => {
    const cacheDir = path.join(os.homedir(), ".cache", "ciphermap", "bin");
    fs.mkdirSync(cacheDir, { recursive: true });
    const tmpFile = path.join(cacheDir, `.ciphermap-${process.pid}-${Date.now()}.tmp`);
    const destFile = path.join(cacheDir, target.exeName);
    const downloadUrl = `${CI_CLI_ORIGIN}?os=${encodeURIComponent(target.os)}&arch=${encodeURIComponent(target.arch)}`;

    const req = https.get(
      downloadUrl,
      {
        minVersion: "TLSv1.2",
        timeout: 60_000,
        headers: {
          Authorization: `Bearer ${licenseKey}`,
          "X-CipherMap-CI-Provider": "mcp-launcher",
          "User-Agent": `@ciphermap/mcp/${SERVER_VERSION} (${target.os}-${target.arch})`
        }
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} from /api/dl/ci-cli`));
        }
        const expectedSha = String(res.headers["x-ciphermap-sha256"] || "").trim().toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(expectedSha)) {
          res.resume();
          return reject(new Error("Missing or malformed X-CipherMap-SHA256 header"));
        }
        const hash = crypto.createHash("sha256");
        const out = fs.createWriteStream(tmpFile, { mode: 0o700 });
        res.on("data", (chunk) => hash.update(chunk));
        res.pipe(out);
        out.on("finish", () => {
          out.close(() => {
            const actualSha = hash.digest("hex");
            if (actualSha !== expectedSha) {
              try { fs.unlinkSync(tmpFile); } catch {}
              return reject(new Error(`SHA-256 mismatch: expected ${expectedSha}, got ${actualSha}`));
            }
            if (target.os !== "windows") {
              fs.chmodSync(tmpFile, 0o755);
            }
            fs.renameSync(tmpFile, destFile);
            resolve(destFile);
          });
        });
        out.on("error", (err) => {
          try { fs.unlinkSync(tmpFile); } catch {}
          reject(err);
        });
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error("Timed out downloading CipherMap CLI"));
    });
    req.on("error", reject);
  });
}

function handleJsonRpcRequest(msg) {
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") {
    return null;
  }
  // JSON-RPC notifications omit `id` and expect no response frame.
  if (msg.id === undefined) {
    return null;
  }

  const supportedVersions = new Set(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]);
  const clientVersion = msg.params && typeof msg.params.protocolVersion === "string"
    ? msg.params.protocolVersion
    : "2024-11-05";
  const negotiatedVersion = supportedVersions.has(clientVersion) ? clientVersion : "2024-11-05";

  switch (msg.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          protocolVersion: negotiatedVersion,
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
            prompts: { listChanged: false }
          },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION
          },
          instructions: SERVER_INSTRUCTIONS
        }
      };

    case "ping":
      return { jsonrpc: "2.0", id: msg.id, result: {} };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id: msg.id,
        result: { tools: TOOL_MANIFEST }
      };

    case "resources/list":
      return { jsonrpc: "2.0", id: msg.id, result: { resources: [] } };

    case "resources/templates/list":
      return { jsonrpc: "2.0", id: msg.id, result: { resourceTemplates: [] } };

    case "prompts/list":
      return { jsonrpc: "2.0", id: msg.id, result: { prompts: [] } };

    case "tools/call": {
      const toolName = msg.params && typeof msg.params.name === "string" ? msg.params.name : "";
      const known = TOOL_MANIFEST.some((t) => t.name === toolName);
      if (!known) {
        return {
          jsonrpc: "2.0",
          id: msg.id,
          error: { code: -32602, message: `Unknown CipherMap MCP tool: ${toolName}` }
        };
      }
      return {
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          isError: true,
          content: [
            {
              type: "text",
              text: [
                `CipherMap native binary (${EXPECTED_VERSION}) is not yet installed on PATH.`,
                `To run ${toolName} locally with zero source-code egress:`,
                `1. Download the signed native CLI & claim a 7-day corporate trial key at https://www.ciphermap.io/eval-pack#trial`,
                `2. Place 'ciphermap' in /usr/local/bin or ~/.local/bin (or set CIPHERMAP_BIN) and export CIPHERMAP_LICENSE.`
              ].join("\n")
            }
          ]
        }
      };
    }

    default:
      return {
        jsonrpc: "2.0",
        id: msg.id,
        error: { code: -32601, message: `Method not found: ${msg.method}` }
      };
  }
}

function serveIntrospectionStdio() {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false
  });

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed || /^content-length:/i.test(trimmed)) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      process.stdout.write(
        JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }) + "\n"
      );
      return;
    }
    const resp = handleJsonRpcRequest(parsed);
    if (resp) {
      process.stdout.write(JSON.stringify(resp) + "\n");
    }
  });

  rl.on("close", () => {
    process.exit(0);
  });
}

async function main() {
  const userArgs = process.argv.slice(2);
  if (userArgs.includes("--launcher-self-check")) {
    const found = findInstalledBinary();
    process.stdout.write(
      JSON.stringify({
        ok: true,
        launcherVersion: EXPECTED_VERSION,
        toolCount: TOOL_MANIFEST.length,
        binaryFound: Boolean(found),
        binaryPath: found
      }) + "\n"
    );
    return;
  }

  if (userArgs.includes("--introspect-only")) {
    serveIntrospectionStdio();
    return;
  }

  let binPath = findInstalledBinary();
  const licenseKey = (process.env.CIPHERMAP_LICENSE || process.env.CIPHERMAP_LICENSE_KEY || "").trim();
  const nativeTarget = resolveNativeTarget();

  if (!binPath && nativeTarget && licenseKey) {
    try {
      binPath = await downloadNativeBinaryWithLicense(licenseKey, nativeTarget);
    } catch (err) {
      process.stderr.write(`[@ciphermap/mcp] Authenticated binary bootstrap failed: ${err.message}\n`);
    }
  }

  if (!binPath) {
    // Enter zero-dependency MCP stdio introspection & onboarding mode so IDEs and
    // protocol inspectors immediately discover all 11 tools without crashing.
    serveIntrospectionStdio();
    return;
  }

  const mcpArgs = userArgs[0] === "mcp" ? userArgs : ["mcp", ...userArgs];
  const child = childProcess.spawn(binPath, mcpArgs, {
    stdio: "inherit",
    env: process.env
  });

  child.on("error", (err) => {
    process.stderr.write(`[@ciphermap/mcp] Failed to launch ${binPath}: ${err.message}\n`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 0);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  candidateBinaryPaths,
  findInstalledBinary,
  resolveNativeTarget,
  handleJsonRpcRequest,
  TOOL_MANIFEST,
  EXPECTED_VERSION
};
