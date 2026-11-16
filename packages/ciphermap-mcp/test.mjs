import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const serverJsonPath = path.join(__dirname, "..", "..", "server.json");
const serverJson = fs.existsSync(serverJsonPath)
  ? JSON.parse(fs.readFileSync(serverJsonPath, "utf8"))
  : null;
const launcher = require("./bin/ciphermap-mcp.js");

test("@ciphermap/mcp package metadata matches Official MCP Registry server.json", () => {
  assert.equal(pkg.mcpName, "io.github.Ciphermap-io/ciphermap-mcp");
  assert.equal(launcher.EXPECTED_VERSION, `v${pkg.version}`);
  assert.equal(launcher.TOOL_MANIFEST.length, 11);
  for (const tool of launcher.TOOL_MANIFEST) {
    assert.equal(typeof tool.name, "string");
    assert.equal(typeof tool.description, "string");
    assert.equal(tool.annotations.openWorldHint, false);
    assert.equal(tool.annotations.destructiveHint, false);
  }
  if (serverJson) {
    assert.equal(pkg.mcpName, serverJson.name);
    assert.equal(pkg.version, serverJson.version);
  }
});

test("@ciphermap/mcp --launcher-self-check locates local ciphermap binary cleanly", () => {
  const cliPath = path.join(__dirname, "bin", "ciphermap-mcp.js");
  const out = execFileSync(process.execPath, [cliPath, "--launcher-self-check"], { encoding: "utf8" });
  const parsed = JSON.parse(out.trim());
  assert.equal(parsed.ok, true);
  assert.equal(parsed.launcherVersion, "v1.0.6");
  assert.equal(parsed.toolCount, 11);
  assert.equal(typeof parsed.binaryFound, "boolean");
});

test("@ciphermap/mcp --introspect-only speaks full MCP JSON-RPC 2.0 over stdio", () => {
  const cliPath = path.join(__dirname, "bin", "ciphermap-mcp.js");
  const frames = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "1.0.0" } } },
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ciphermap_scan_all", arguments: {} } },
    { jsonrpc: "2.0", id: 4, method: "ping" }
  ];
  const res = spawnSync(process.execPath, [cliPath, "--introspect-only"], {
    input: frames.map((f) => JSON.stringify(f)).join("\n") + "\n",
    encoding: "utf8"
  });
  assert.equal(res.status, 0);
  const lines = res.stdout.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 4);
  assert.equal(lines[0].id, 1);
  assert.equal(lines[0].result.serverInfo.name, "io.github.Ciphermap-io/ciphermap-mcp");
  assert.equal(lines[1].id, 2);
  assert.equal(lines[1].result.tools.length, 11);
  assert.equal(lines[2].id, 3);
  assert.equal(lines[2].result.isError, true);
  assert.match(lines[2].result.content[0].text, /eval-pack#trial/);
  assert.equal(lines[3].id, 4);
});
