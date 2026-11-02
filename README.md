# CipherMap Local MCP Referee & CI/CD Integration Guide

Configuration templates and reference workflows for running **[CipherMap](https://www.ciphermap.io)** (`v1.0.0`) as:
1. A **100% local `stdio` Model Context Protocol (MCP) AI Referee** inside **Claude Code**, **Cursor**, and **Windsurf** (`ciphermap mcp --workspace .`).
2. A **zero-egress CI/CD gate & signed CycloneDX 1.6 CBOM generator** in **GitHub Actions** and **GitLab CI**.

> **Zero Source Egress:** CipherMap ships as native Apple Developer ID (`ZLF7244KA7`) and Microsoft Authenticode signed binaries ([download evaluation pack](https://www.ciphermap.io/eval-pack)). No source code, keys, or AST fragments ever leave your workstation or self-hosted runner (`--offline --no-telemetry`).

---

## 1. Local `stdio` MCP Server (`ciphermap mcp`)

CipherMap's Tier B Enterprise MCP server runs locally over `stdio` JSON-RPC 2.0 with zero open network sockets and exposes **4 deterministic verification tools**:

| MCP Tool | Purpose |
|---|---|
| `ciphermap_scan_all` | Runs local 12-language PQC (`PQC-*`, `PQC-PRE-001..005`) and structural bug-class (`IMM-*`) discovery on the workspace. |
| `ciphermap_inspect_rule` | Returns NIST FIPS 203/204/205, CNSA 2.0, CWE, and protocol-safety constraints for any rule ID before an AI coding agent drafts a patch. |
| `ciphermap_verify_candidate_fix` | Runs AST/taint verification, compiler build, repository test suite, and network-denied OS witness gates on a candidate diff—returning structured rejection diagnostics if unsafe. |
| `ciphermap_verify_workspace_clean` | Verifies the workspace passes active policy and monotonic ratchet thresholds (`0` regressions) prior to commit. |

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "ciphermap": {
      "command": "ciphermap",
      "args": ["mcp", "--workspace", "."]
    }
  }
}
```

### Claude Code (`.mcp.json` or `~/.claude.json`)

```json
{
  "mcpServers": {
    "ciphermap": {
      "type": "stdio",
      "command": "ciphermap",
      "args": ["mcp", "--workspace", "."]
    }
  }
}
```

### Synthesizing `.cursor/rules` & `CLAUDE.md` Guardrails

```bash
ciphermap immunity emit-agent-rules . --write
```

---

## 2. Zero-Egress CycloneDX 1.6 CBOM & SARIF in GitHub Actions

```yaml
name: PQC & CycloneDX 1.6 CBOM Gate
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  pqc-cbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Free Offline PQC SARIF Scan
        run: |
          ciphermap scan . --offline --no-telemetry --exclude-vendored --format sarif -o results.sarif
          ciphermap scan . --offline --no-telemetry --exclude-vendored --fail-on high

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Generate Signed CycloneDX 1.6 CBOM (Tier A / Pro Trial)
        if: env.CIPHERMAP_LICENSE != ''
        env:
          CIPHERMAP_LICENSE: ${{ secrets.CIPHERMAP_LICENSE }}
        run: |
          ciphermap cbom . --offline --no-telemetry -o cbom.cdx.json
```

---

## Links & Specifications

- **Evaluation Pack (macOS / Linux / Windows signed CLI):** [https://www.ciphermap.io/eval-pack](https://www.ciphermap.io/eval-pack)
- **7-Day Tier A Pro Trial (Signed CBOM Export):** [https://www.ciphermap.io/beta](https://www.ciphermap.io/beta)
- **Full CLI Reference:** [https://www.ciphermap.io/docs](https://www.ciphermap.io/docs)
- **Technical Comparison Matrix:** [https://www.ciphermap.io/compare](https://www.ciphermap.io/compare)
- **LLM Technical Reference:** [https://www.ciphermap.io/llms-full.txt](https://www.ciphermap.io/llms-full.txt)

## License

Documentation and configuration templates in this repository are licensed under the MIT License. CipherMap CLI binaries are proprietary software published by Ciphermap Technologies LLC ([commercial terms](https://www.ciphermap.io/terms)).
