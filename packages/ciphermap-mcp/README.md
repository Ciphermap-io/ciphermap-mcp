# `@ciphermap/mcp` — Zero-Egress Local `stdio` MCP Referee

[![Official MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.Ciphermap--io%2Fciphermap--mcp-7c3aed)](https://registry.modelcontextprotocol.io/v0/servers?search=ciphermap)
[![Zero Source Egress](https://img.shields.io/badge/Source%20Egress-0%20bytes%20(--offline)-10b981)](https://www.ciphermap.io/integrations?utm_source=npm_mcp&utm_medium=readme)
[![CycloneDX CBOM](https://img.shields.io/badge/CycloneDX-1.6%20%26%201.7%20CBOM-0ea5e9)](https://www.ciphermap.io/docs?utm_source=npm_mcp&utm_medium=readme#cbom)
[![License: MIT](https://img.shields.io/badge/License-MIT-slate.svg)](LICENSE)

Zero-dependency local `stdio` Model Context Protocol (MCP) launcher for **[CipherMap](https://www.ciphermap.io?utm_source=npm_mcp&utm_medium=readme)** (`v1.0.6` native CLI). Exposes **11 deterministic post-quantum cryptography (PQC), CycloneDX 1.7 CBOM, 16-mandate compliance, and 4-Gate compiler-verified Immunity tools** directly inside **Claude Code**, **Cursor**, **VS Code (`@mcp`)**, **GitHub Copilot**, and **Windsurf** — with **0 bytes of source code, keystore, or prompt egress**.

- **Official MCP Registry ID:** `io.github.Ciphermap-io/ciphermap-mcp`
- **Signed Native Binaries:** Apple Developer ID (`ZLF7244KA7`, **Apple Notarized**) on macOS (`arm64` / `amd64`), **Microsoft Public-Trust Authenticode** on Windows (`amd64` / `arm64`), and Ed25519 `.text`-sealed static Linux binaries (`amd64` / `arm64`).
- **Signed Offline CLI & Guided Evaluation:** [ciphermap.io/eval-pack](https://www.ciphermap.io/eval-pack?utm_source=npm_mcp&utm_medium=readme) · [Book 20-Min Live Repo Proof](https://www.ciphermap.io/book?utm_source=npm_mcp&utm_medium=readme) · [Commercial Plans](https://www.ciphermap.io/pricing?utm_source=npm_mcp&utm_medium=readme)
- **Source & Multi-SCM CI Templates:** [github.com/Ciphermap-io/ciphermap-mcp](https://github.com/Ciphermap-io/ciphermap-mcp)

---

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
      "args": ["-y", "@ciphermap/mcp", "--workspace", "."],
      "env": {
        "CIPHERMAP_LICENSE": "${env:CIPHERMAP_LICENSE}"
      }
    }
  }
}
```

### How Binary Resolution Works (`0` Bundled Binaries, `0` Source Egress)
1. **Local Binary First:** Uses `ciphermap` already installed on `PATH`, `CIPHERMAP_BIN`, `/usr/local/bin/ciphermap`, `/opt/homebrew/bin/ciphermap`, `~/.local/bin/ciphermap`, or `~/.cache/ciphermap/bin/ciphermap`.
2. **Authenticated Multi-OS Bootstrap (Optional):** When `CIPHERMAP_LICENSE` is set and no local binary exists, downloads the signed native CLI for your OS/CPU (`darwin-arm64`, `darwin-amd64`, `windows-amd64`, `windows-arm64`, `linux-amd64`, `linux-arm64`) over TLS 1.2+ from `https://www.ciphermap.io/api/dl/ci-cli`, verifies the 64-hex `X-CipherMap-SHA256` digest, and atomically installs it into `~/.cache/ciphermap/bin/`.
3. **Zero-Config IDE Introspection:** If no binary or key is present yet, serves full MCP JSON-RPC 2.0 (`Content-Length` + newline framing) so IDEs immediately discover all 11 tool schemas and link directly to CLI and evaluation setup.

---

## 11 Deterministic Local MCP Tools

| MCP Tool | Capability |
|---|---|
| `ciphermap_scan_all` | 12-language PQC (`PQC-*`, `PQC-PRE-001..005`, `.jar`/`.whl`/`.p12`/`.jks`) + 12 Immunity families (`IMM-*`, `IMM-AICFG-001`) local discovery. |
| `ciphermap_check_baseline_health` | Sandboxed `T0` compiler/typecheck baseline probes and formal `T0`/`T1` fault attribution before agent edits. |
| `ciphermap_inspect_rule` | Returns NIST FIPS 203/204/205, CNSA 2.0, `SC-081` 47-day TLS, and CWE contracts before code drafting. |
| `ciphermap_recommend_pqc_sdk` | Recommends constant-time finalized FIPS 203 (`ML-KEM`), FIPS 204 (`ML-DSA`), and FIPS 205 (`SLH-DSA`) libraries. |
| `ciphermap_verify_dependencies` | Firewalls proposed crypto packages against slopsquatting and timing-unsafe fallbacks. |
| `ciphermap_extinguish_immunity` | Synthesizes polyglot AST & `.cursorrules`/`CLAUDE.md`/`.mcp.json` codemods verified via 4-Gate compiler/test witnesses + `ddmin` salvage. |
| `ciphermap_verify_candidate_fix` | Stages candidate edits inside an ephemeral network-denied sandbox copy (never mutating live files) and returns structured counterexamples on failure. |
| `ciphermap_verify_workspace_clean` | Verifies zero remaining blockers and validates dual `Ed25519 + ML-DSA-65` ProofBundles prior to commit. |
| `ciphermap_generate_cbom` | Emits deterministic CycloneDX 1.7 or 1.6 (ECMA-424) CBOM summaries across source, archives, and keystores. |
| `ciphermap_generate_pqc_wrapper` | Previews zero-code compensating PQC termination configs (`Envoy`, `NGINX`, `HAProxy`, `Caddy`, `Traefik`, `Apache`, `stunnel`, `K8s`, `IPsec`, `cert-manager`, `CNSA 2.0`). |
| `ciphermap_compliance_crosswalk` | Maps workspace cryptographic assets across **16 global regulatory mandates** (`CNSA 2.0`, `PCI-DSS 4.0.1`, `FedRAMP`, `CMMC 2.0`, `EU DORA`, `NIS2`, `OSCAL 1.1.2`, etc.). |

---

## Documentation & Enterprise Support

- **Integrations & CI/CD Setup:** [ciphermap.io/integrations](https://www.ciphermap.io/integrations?utm_source=npm_mcp&utm_medium=readme)
- **Full CLI & MCP Docs:** [ciphermap.io/docs](https://www.ciphermap.io/docs?utm_source=npm_mcp&utm_medium=readme)
- **GitHub Marketplace Action (`Ciphermap-io/ciphermap-action`):** [github.com/marketplace/actions/ciphermap-pqc-cbom-scan](https://github.com/marketplace/actions/ciphermap-pqc-cbom-scan)
- **Security Policy:** [SECURITY.md](https://github.com/Ciphermap-io/ciphermap-mcp/blob/main/SECURITY.md)
