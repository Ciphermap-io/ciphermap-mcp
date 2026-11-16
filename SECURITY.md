# Security Policy

## Supported Versions

| Version | Registry Status | Supported |
|---|---|---|
| `1.0.6` (`v1.0.6`) | Active on `registry.modelcontextprotocol.io` | ✅ Supported |
| `< 1.0.6` | Superseded | ⚠️ Upgrade to `1.0.6` |

## Zero-Egress MCP Security Architecture

- **Stdio Only, Zero Open Sockets:** `ciphermap mcp` communicates strictly over local JSON-RPC 2.0 `stdio` (`openWorldHint: false`) and enforces `--offline --no-telemetry` in-process so repository code never leaves the developer workstation.
- **Confined Ephemeral Sandbox:** Candidate patch verification (`ciphermap_verify_candidate_fix`) stages proposed edits inside a temporary sandbox copy without mutating live workspace files until explicitly approved.
- **Agent Configuration Shield (`IMM-AICFG-001`):** Detects invisible Unicode bidirectional/tag smuggling (`Sneaky Bits`) and rogue command/exfiltration hooks across `.cursorrules`, `CLAUDE.md`, `.windsurfrules`, `GEMINI.md`, and `.mcp.json`.

## Reporting a Vulnerability

Please report security issues privately to **security@ciphermap.io** (see `https://www.ciphermap.io/.well-known/security.txt`). Do not open public GitHub issues for undisclosed vulnerabilities.
