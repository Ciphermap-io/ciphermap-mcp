#!/usr/bin/env node
"use strict";

/**
 * @ciphermap/mcp — Zero-dependency stdio launcher for `ciphermap mcp`.
 *
 * Security invariants:
 *   1. Prefers a verified local `ciphermap` binary already installed on PATH,
 *      `/usr/local/bin/ciphermap`, `~/.local/bin/ciphermap`, or `~/.cache/ciphermap/bin/ciphermap`.
 *   2. On Linux x86_64 when `CIPHERMAP_LICENSE` is set and no local binary exists,
 *      authenticates over TLS 1.2+ to `https://www.ciphermap.io/api/dl/ci-cli` and
 *      verifies the `X-CipherMap-SHA256` digest before chmod + atomic rename.
 *   3. Never opens network sockets during MCP session execution (`ciphermap mcp`
 *      enforces `--offline --no-telemetry` in-process).
 */

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const EXPECTED_VERSION = "v1.0.6";
const CI_CLI_ORIGIN = "https://www.ciphermap.io/api/dl/ci-cli";

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

function downloadLinuxX64WithLicense(licenseKey) {
  return new Promise((resolve, reject) => {
    const cacheDir = path.join(os.homedir(), ".cache", "ciphermap", "bin");
    fs.mkdirSync(cacheDir, { recursive: true });
    const tmpFile = path.join(cacheDir, `.ciphermap-${process.pid}-${Date.now()}.tmp`);
    const destFile = path.join(cacheDir, "ciphermap");

    const req = https.get(
      CI_CLI_ORIGIN,
      {
        minVersion: "TLSv1.2",
        timeout: 60_000,
        headers: {
          Authorization: `Bearer ${licenseKey}`,
          "X-CipherMap-CI-Provider": "mcp-npx-launcher",
          "User-Agent": `@ciphermap/mcp/${EXPECTED_VERSION.slice(1)}`
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
            fs.chmodSync(tmpFile, 0o755);
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

async function main() {
  const userArgs = process.argv.slice(2);
  if (userArgs.includes("--launcher-self-check")) {
    const found = findInstalledBinary();
    process.stdout.write(JSON.stringify({ ok: true, launcherVersion: EXPECTED_VERSION, binaryFound: Boolean(found), binaryPath: found }) + "\n");
    return;
  }

  let binPath = findInstalledBinary();
  const licenseKey = (process.env.CIPHERMAP_LICENSE || process.env.CIPHERMAP_LICENSE_KEY || "").trim();

  if (!binPath && process.platform === "linux" && process.arch === "x64" && licenseKey) {
    try {
      binPath = await downloadLinuxX64WithLicense(licenseKey);
    } catch (err) {
      process.stderr.write(`[@ciphermap/mcp] Authenticated binary bootstrap failed: ${err.message}\n`);
    }
  }

  if (!binPath) {
    process.stderr.write(
      [
        `[@ciphermap/mcp] CipherMap native binary (${EXPECTED_VERSION}) was not found on PATH.`,
        `Install the Apple-Notarized / Authenticode-signed evaluation binary in 60 seconds:`,
        `  -> https://www.ciphermap.io/eval-pack#trial`,
        `Then place 'ciphermap' in /usr/local/bin or ~/.local/bin (or set CIPHERMAP_BIN).`
      ].join("\n") + "\n"
    );
    process.exit(1);
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

module.exports = { candidateBinaryPaths, findInstalledBinary, EXPECTED_VERSION };
