import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const serverJson = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "server.json"), "utf8"));
const launcher = require("./bin/ciphermap-mcp.js");

test("@ciphermap/mcp package metadata matches Official MCP Registry server.json", () => {
  assert.equal(pkg.mcpName, serverJson.name);
  assert.equal(pkg.version, serverJson.version);
  assert.equal(launcher.EXPECTED_VERSION, `v${serverJson.version}`);
});

test("@ciphermap/mcp --launcher-self-check locates local ciphermap binary cleanly", () => {
  const cliPath = path.join(__dirname, "bin", "ciphermap-mcp.js");
  const out = execFileSync(process.execPath, [cliPath, "--launcher-self-check"], { encoding: "utf8" });
  const parsed = JSON.parse(out.trim());
  assert.equal(parsed.ok, true);
  assert.equal(parsed.launcherVersion, "v1.0.6");
  assert.equal(typeof parsed.binaryFound, "boolean");
});
