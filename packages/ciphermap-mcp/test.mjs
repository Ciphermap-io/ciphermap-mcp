const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const pkg = require("./package.json");
const launcher = require("./bin/ciphermap-mcp.js");

test("@ciphermap/mcp package metadata matches Official MCP Registry server.json", () => {
  const serverJson = require("../../server.json");
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
