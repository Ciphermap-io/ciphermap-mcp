<!-- mcp-name: io.github.Ciphermap-io/ciphermap-mcp -->

# CipherMap Local MCP Referee, `pre-commit` Hook & Multi-SCM CI Integration (`v1.0.6`)

[![Validate MCP Server Schema & Stdio Protocol](https://github.com/Ciphermap-io/ciphermap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Ciphermap-io/ciphermap-mcp/actions/workflows/ci.yml)
[![Official MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.Ciphermap--io%2Fciphermap--mcp-7c3aed)](https://registry.modelcontextprotocol.io/v0/servers?search=ciphermap)
[![Ciphermap-io/ciphermap-mcp MCP server](https://glama.ai/mcp/servers/Ciphermap-io/ciphermap-mcp/badges/score.svg)](https://glama.ai/mcp/servers/Ciphermap-io/ciphermap-mcp)
[![CycloneDX CBOM](https://img.shields.io/badge/CycloneDX-1.6%20%26%201.7%20CBOM-0ea5e9)](https://cyclonedx.org/tool-center/)
[![License: MIT](https://img.shields.io/badge/License-MIT-slate.svg)](LICENSE)

Configuration templates, `pre-commit` hook definitions, and Official MCP Registry metadata (`server.json`) for running **[CipherMap](https://www.ciphermap.io/?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=hero_brand)** (`v1.0.6`) as:
1. A **100% local `stdio` Model Context Protocol (MCP) Referee** (`11` tools, `0` open network sockets) inside **Claude Code**, **Cursor**, **VS Code (`@mcp`)**, **GitHub Copilot**, and **Windsurf** (`ciphermap mcp --workspace .`).
2. A **shift-left `pre-commit` hook** scanning staged diffs in `<250ms` (`--staged --offline`).
3. A **zero-egress CI/CD gate & signed CycloneDX 1.6 / 1.7 (ECMA-424) CBOM generator** across **GitHub Actions**, **Bitbucket Pipelines / Data Center**, **GitLab CI**, and **Azure DevOps**.

[![Public GitHub Repo PQC Scanner](https://www.ciphermap.io/scan/badge/github/open-quantum-safe/liboqs-go)](https://www.ciphermap.io/scan?utm_source=mcp_readme&utm_medium=badge&utm_campaign=mcp_ecosystem&utm_content=scan_badge)

> **Zero Source Egress:** CipherMap ships as native Apple Developer ID (`ZLF7244KA7`, Apple Notarized) and Microsoft Authenticode signed binaries ([download evaluation pack](https://www.ciphermap.io/eval-pack?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=eval_pack)). No source code, `.p12`/`.jks` keystores, or AST fragments ever leave your workstation or self-hosted runner (`--offline --no-telemetry`).

---

## 1. Local `stdio` MCP Server (`ciphermap mcp` — 11 Tools in `v1.0.6`)

CipherMap's local MCP server auto-detects both newline-delimited JSON-RPC 2.0 and `Content-Length` framed `stdio` with zero network egress, exposing **11 deterministic verification & compliance tools**:

| MCP Tool | Purpose |
|---|---|
| `ciphermap_scan_all` | Runs local 12-language PQC (`PQC-*`, `PQC-PRE-001..005`, `.jar`/`.p12`) and structural handler/AI-config (`IMM-*`, `IMM-AICFG-001`) discovery. |
| `ciphermap_check_baseline_health` | Runs sandboxed `T0` compiler/typecheck health probes and formal `T0`/`T1` fault attribution before edits. |
| `ciphermap_inspect_rule` | Returns NIST FIPS 203/204/205, CNSA 2.0, `SC-081` 100-day TLS, CWE, and wire-protocol constraints before an agent drafts code. |
| `ciphermap_recommend_pqc_sdk` | Recommends constant-time finalized FIPS 203 (`ML-KEM`), FIPS 204 (`ML-DSA`), and FIPS 205 (`SLH-DSA`) libraries (preventing Round-3 `kyber768`/`dilithium3` drift). |
| `ciphermap_verify_dependencies` | Firewalls proposed PQC/crypto packages against slopsquatting and timing-unsafe fallbacks. |
| `ciphermap_extinguish_immunity` | Synthesizes polyglot AST & `.cursorrules`/`CLAUDE.md`/`.mcp.json` codemods verified via 4-Gate compiler/test witnesses + `ddmin` salvage. |
| `ciphermap_verify_candidate_fix` | Stages candidate edits inside an ephemeral network-denied sandbox copy (never mutating live files) and returns structured counterexamples on failure. |
| `ciphermap_verify_workspace_clean` | Verifies zero remaining policy blockers and validates `Ed25519 + ML-DSA-65` ProofBundles prior to commit. |
| `ciphermap_generate_cbom` | Emits deterministic CycloneDX 1.7 or 1.6 (ECMA-424) CBOM summaries across source, `.jar`/`.whl` archives, and `.p12`/`.jks` keystores. |
| `ciphermap_generate_pqc_wrapper` | Previews zero-code compensating PQC termination configs (`Envoy`, `NGINX`, `HAProxy`, `Caddy`, `Traefik`, `Apache`, `stunnel`, `K8s`, `IPsec`, `cert-manager`, `CNSA 2.0`). |
| `ciphermap_compliance_crosswalk` | Maps workspace cryptographic assets across **16 global regulatory mandates** (`CNSA 2.0`, `PCI-DSS 4.0.1`, `FedRAMP`, `CMMC 2.0`, `EU DORA`, `NIS2`, `OSCAL 1.1.2`, etc.). |

### Cursor (`.cursor/mcp.json`) & VS Code (`.vscode/mcp.json`)

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

### Emit 5-Agent Herd-Immunity Guardrails (`Cursor`, `Claude Code`, `Copilot`, `Windsurf`, `Gemini`)

```bash
ciphermap immunity emit-agent-rules . --write
```

Ready-to-copy starter rules generated by `v1.0.6` (`11` polyglot immunity + NIST FIPS 203/204/205 guardrails) are also available directly in [`examples/agent-rules/`](./examples/agent-rules/):
- [`examples/agent-rules/.cursor/rules/ciphermap-immunity.mdc`](./examples/agent-rules/.cursor/rules/ciphermap-immunity.mdc)
- [`examples/agent-rules/CLAUDE.md`](./examples/agent-rules/CLAUDE.md)
- [`examples/agent-rules/.github/copilot-instructions.md`](./examples/agent-rules/.github/copilot-instructions.md)
- [`examples/agent-rules/.windsurfrules`](./examples/agent-rules/.windsurfrules)
- [`examples/agent-rules/GEMINI.md`](./examples/agent-rules/GEMINI.md)

---

## 2. Shift-Left `pre-commit` Hook (`<250ms` Offline Staged Scan)

Add to `.pre-commit-config.yaml` to block legacy crypto regressions, Round-3 `kyber768` hallucinations, and Trojan Unicode `.cursorrules`/`CLAUDE.md` poisoning (`IMM-AICFG-001`) before commit:

```yaml
repos:
  - repo: https://github.com/Ciphermap-io/ciphermap-mcp
    rev: v1.0.6
    hooks:
      - id: ciphermap
```

---

## 3. Enterprise GitHub Actions (`Ciphermap-io/ciphermap-action`), GitLab CI Catalog & OWASP Dependency-Track (`v4` & `v5`)

- **Full Dependency-Track `v4.12–4.14` (`--dt-compat v4` lossless carrier) & `v5.x Hyades` (`--dt-compat v5` native `cryptographic-asset`) Guide:** [`docs/dependency-track-cbom-guide.md`](./docs/dependency-track-cbom-guide.md)
- **GitLab 17+/18+ CI/CD Catalog Component Template:** [`examples/gitlab-ci/pqc-cbom-gate.yml`](./examples/gitlab-ci/pqc-cbom-gate.yml)

Use [`Ciphermap-io/ciphermap-action`](https://github.com/Ciphermap-io/ciphermap-action) (pinned to its immutable 40-char commit SHA) to upload SARIF 2.1.0 to **GitHub Code Scanning** and push signed **CycloneDX 1.6 / 1.7 CBOMs** into **OWASP Dependency-Track (`v4` or `v5`)**:

```yaml
      - name: Run CipherMap Zero-Egress PQC & CycloneDX 1.7 CBOM Gate
        uses: Ciphermap-io/ciphermap-action@e14c236d4cc55a85ca5c13054256b968b40cbf22 # v1.0.6
        with:
          fail-on: high
          target: cnsa-2.0
          include-archives: "true"
          cbom-file: cbom.cdx.json
          cbom-spec-version: "1.7"
          license-key: ${{ secrets.CIPHERMAP_LICENSE }}

      - name: Upload CycloneDX 1.7 CBOM to OWASP Dependency-Track v5 (Optional)
        if: env.DTRACK_API_KEY != ''
        env:
          DTRACK_URL: ${{ secrets.DTRACK_URL }}
          DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
          DTRACK_PROJECT_UUID: ${{ secrets.DTRACK_PROJECT_UUID }}
        run: |
          curl --proto '=https' --tlsv1.2 -fsSL -X POST "${DTRACK_URL}/api/v1/bom" \
            -H "X-Api-Key: ${DTRACK_API_KEY}" \
            -F "project=${DTRACK_PROJECT_UUID}" \
            -F "bom=@cbom.cdx.json"
```

- **Instant Public GitHub & Bitbucket URL Scanner:** [ciphermap.io/scan](https://www.ciphermap.io/scan?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=footer_scan)
- **Methodology & Scope Boundaries:** [ciphermap.io/methodology](https://www.ciphermap.io/methodology?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=footer_methodology)
- **3PAO / QSA Assessor Workbench & 1-Page InfoSec Zero-Egress Memo:** [ciphermap.io/for-assessors](https://www.ciphermap.io/for-assessors?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=footer_assessors) · [ciphermap.io/procurement-memo](https://www.ciphermap.io/procurement-memo?utm_source=mcp_readme&utm_medium=readme&utm_campaign=mcp_ecosystem&utm_content=footer_memo)
