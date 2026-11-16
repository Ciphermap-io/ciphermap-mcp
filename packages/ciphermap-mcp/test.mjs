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

test("@ciphermap/mcp package metadata, LICENSE & Official MCP Registry server.json parity", () => {
  assert.equal(pkg.mcpName, "io.github.Ciphermap-io/ciphermap-mcp");
  assert.equal(pkg.publishConfig?.access, "public");
  assert.equal(pkg.repository?.directory, "packages/ciphermap-mcp");
  assert.equal(fs.existsSync(path.join(__dirname, "LICENSE")), true);
  assert.equal(launcher.SERVER_VERSION, pkg.version);
  assert.match(launcher.EXPECTED_CLI_VERSION, /^v\d+\.\d+\.\d+$/);
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

test("@ciphermap/mcp --launcher-self-check reports decoupled launcherVersion and expectedCliVersion", () => {
  const cliPath = path.join(__dirname, "bin", "ciphermap-mcp.js");
  const out = execFileSync(process.execPath, [cliPath, "--launcher-self-check"], { encoding: "utf8" });
  const parsed = JSON.parse(out.trim());
  assert.equal(parsed.ok, true);
  assert.equal(parsed.launcherVersion, pkg.version);
  assert.equal(parsed.expectedCliVersion, "v1.0.6");
  assert.equal(parsed.toolCount, 11);
  assert.equal(typeof parsed.binaryFound, "boolean");
});

test("@ciphermap/mcp --introspect-only speaks newline-delimited MCP JSON-RPC 2.0 over stdio", () => {
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
  assert.equal(lines[0].result.serverInfo.version, pkg.version);
  assert.equal(lines[1].id, 2);
  assert.equal(lines[1].result.tools.length, 11);
  assert.equal(lines[2].id, 3);
  assert.equal(lines[2].result.isError, true);
  assert.match(lines[2].result.content[0].text, /eval-pack#trial/);
  assert.equal(lines[3].id, 4);
});

test("@ciphermap/mcp --introspect-only speaks Content-Length framed JSON-RPC 2.0 without trailing newline", () => {
  const cliPath = path.join(__dirname, "bin", "ciphermap-mcp.js");
  const encodeClFrame = (obj) => {
    const json = JSON.stringify(obj);
    const bytes = Buffer.byteLength(json, "utf8");
    return `Content-Length: ${bytes}\r\n\r\n${json}`;
  };
  const inputPayload =
    encodeClFrame({
      jsonrpc: "2.0",
      id: 10,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "glama-inspector-🛡️", version: "1.0.0" } }
    }) +
    encodeClFrame({ jsonrpc: "2.0", id: 11, method: "tools/list", params: {} });

  const res = spawnSync(process.execPath, [cliPath, "--introspect-only"], {
    input: inputPayload,
    encoding: "utf8"
  });
  assert.equal(res.status, 0);
  assert.match(res.stdout, /^Content-Length:\s*\d+\r\n\r\n\{/);

  const rawBuf = Buffer.from(res.stdout, "utf8");
  const decoded = [];
  let offset = 0;
  while (offset < rawBuf.length) {
    const sep = rawBuf.indexOf("\r\n\r\n", offset);
    assert.ok(sep > offset, "expected CRLFCRLF header separator");
    const hdr = rawBuf.subarray(offset, sep).toString("latin1");
    const len = Number.parseInt(/Content-Length:\s*(\d+)/i.exec(hdr)[1], 10);
    const bodyStart = sep + 4;
    decoded.push(JSON.parse(rawBuf.subarray(bodyStart, bodyStart + len).toString("utf8")));
    offset = bodyStart + len;
  }
  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].id, 10);
  assert.equal(decoded[0].result.protocolVersion, "2025-06-18");
  assert.equal(decoded[1].id, 11);
  assert.equal(decoded[1].result.tools.length, 11);
});

test("@ciphermap/mcp resolveNativeTarget maps macOS, Windows, and Linux x64/arm64 cleanly", () => {
  assert.deepEqual(launcher.resolveNativeTarget("darwin", "arm64"), { os: "darwin", arch: "arm64", exeName: "ciphermap" });
  assert.deepEqual(launcher.resolveNativeTarget("darwin", "x64"), { os: "darwin", arch: "amd64", exeName: "ciphermap" });
  assert.deepEqual(launcher.resolveNativeTarget("win32", "x64"), { os: "windows", arch: "amd64", exeName: "ciphermap.exe" });
  assert.deepEqual(launcher.resolveNativeTarget("win32", "arm64"), { os: "windows", arch: "arm64", exeName: "ciphermap.exe" });
  assert.deepEqual(launcher.resolveNativeTarget("linux", "x64"), { os: "linux", arch: "amd64", exeName: "ciphermap" });
  assert.deepEqual(launcher.resolveNativeTarget("linux", "arm64"), { os: "linux", arch: "arm64", exeName: "ciphermap" });
  assert.equal(launcher.resolveNativeTarget("freebsd", "x64"), null);
});
