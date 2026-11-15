# `@ciphermap/mcp` — Zero-Egress Local `stdio` MCP Referee Launcher

Thin zero-dependency launcher for **[CipherMap](https://www.ciphermap.io)** (`v1.0.6`) exposing **11 deterministic local verification & compliance tools** over `stdio` (`--offline --no-telemetry`) for **Claude Code**, **Cursor**, **VS Code (`@mcp`)**, **GitHub Copilot**, and **Windsurf**.

- **Official MCP Registry ID:** `io.github.Ciphermap-io/ciphermap-mcp`
- **Source & CI Templates:** [https://github.com/Ciphermap-io/ciphermap-mcp](https://github.com/Ciphermap-io/ciphermap-mcp)
- **Claim Free 7-Day Corporate Trial Key / Binary:** [https://www.ciphermap.io/eval-pack#trial](https://www.ciphermap.io/eval-pack#trial)

## Quickstart

### Claude Code
```bash
claude mcp add ciphermap -- npx -y @ciphermap/mcp --workspace .
```

### Cursor (`.cursor/mcp.json`) & VS Code (`.vscode/mcp.json`)
```json
{
  "mcpServers": {
    "ciphermap": {
      "command": "npx",
      "args": ["-y", "@ciphermap/mcp", "--workspace", "."]
    }
  }
}
```
