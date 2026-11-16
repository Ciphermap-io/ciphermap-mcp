# OWASP Dependency-Track (`v4.12–4.14` & `v5.x Hyades`) CBOM Ingestion Guide

CipherMap (`v1.0.6+`) generates deterministic, schema-verified **CycloneDX `1.6` and `1.7` (ECMA-424) Cryptographic Bills of Materials (CBOMs)** across 12 source languages, `.jar`/`.war`/`.ear`/`.whl` archives, `.p12`/`.pfx`/`.jks` keystores, and live runtime TLS/SSH observations — and uploads them directly to **OWASP Dependency-Track** without losing cryptographic metadata.

---

## 1. Why Dependency-Track `4.12–4.14` vs. `5.x` Needs `--dt-compat`

| Dependency-Track Version | Upstream Ingestion Behavior | What CipherMap `--dt-compat` Does |
|---|---|---|
| **OWASP Dependency-Track `v4.12.x – v4.14.x`** *(Most widely deployed enterprise release)* | Upstream DT `4.x` has a known BOM classifier bug where `type: "cryptographic-asset"` components in CycloneDX `1.6` are **silently dropped** during asynchronous BOM processing, leaving projects with `0` visible crypto components. | **`--dt-compat v4` (or `auto`)**: Losslessly projects every `cryptographic-asset` into a `type: "file"` carrier preserving full `cdx:cbom:*` algorithm, primitive, key-size, OID, and `evidence.occurrences` properties, polls `/api/v1/bom/token/{uuid}` until async ingestion finishes, and reads back `/api/v1/component/project/{uuid}` to fail closed if any asset was dropped. |
| **OWASP Dependency-Track `v5.x` (`Hyades`)** | Native first-class `type: "cryptographic-asset"` ingestion with CycloneDX `1.6` envelope validation. | **`--dt-compat v5` (or `auto`)**: Uploads native `type: "cryptographic-asset"` components directly (automatically normalizing `1.7`-only fields when targeting DT `5.0` endpoints). |

---

## 2. Direct Zero-Temp-File CLI Upload (`--dt-compat auto`)

Pass credentials via environment variables (`$CIPHERMAP_DEPENDENCY_TRACK_API_KEY`, `$CIPHERMAP_DEPENDENCY_TRACK_URL`, `$CIPHERMAP_DEPENDENCY_TRACK_PROJECT_ID`) so API keys never appear in `ps` process arguments:

```bash
export CIPHERMAP_LICENSE="CIPHERMAP-ENTERPRISE-..."
export CIPHERMAP_DEPENDENCY_TRACK_URL="https://dtrack.internal.example.com"
export CIPHERMAP_DEPENDENCY_TRACK_API_KEY="odt_..."
export CIPHERMAP_DEPENDENCY_TRACK_PROJECT_ID="00000000-0000-0000-0000-000000000000"

ciphermap cbom . \
  --offline \
  --no-telemetry \
  --include-archives \
  --spec-version 1.6 \
  --dt-compat auto \
  --push-url "${CIPHERMAP_DEPENDENCY_TRACK_URL}" \
  --project-id "${CIPHERMAP_DEPENDENCY_TRACK_PROJECT_ID}"
```

- Force explicit `v4` carrier mode: `--dt-compat v4`
- Force explicit `v5` native `cryptographic-asset` mode: `--dt-compat v5`

---

## 3. GitHub Actions Workflow (`Ciphermap-io/ciphermap-action` -> Dependency-Track)

```yaml
name: CipherMap Signed CBOM -> OWASP Dependency-Track
on:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  cbom-sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Scan & Generate Signed CycloneDX CBOM + SARIF
        uses: Ciphermap-io/ciphermap-action@928f39ae18db1ce5f69503eded1bc38cdfe6a127 # v1.0.6
        with:
          fail-on: high
          target: cnsa-2.0
          include-archives: "true"
          cbom-file: cbom.cdx.json
          cbom-spec-version: "1.6"
          license-key: ${{ secrets.CIPHERMAP_LICENSE }}

      - name: Push CBOM to OWASP Dependency-Track (v4 & v5 Auto-Compatible)
        env:
          CIPHERMAP_LICENSE: ${{ secrets.CIPHERMAP_LICENSE }}
          CIPHERMAP_DEPENDENCY_TRACK_URL: ${{ secrets.DTRACK_URL }}
          CIPHERMAP_DEPENDENCY_TRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
          CIPHERMAP_DEPENDENCY_TRACK_PROJECT_ID: ${{ secrets.DTRACK_PROJECT_UUID }}
        run: |
          "${CIPHERMAP_EXECUTABLE}" cbom . \
            --offline \
            --no-telemetry \
            --include-archives \
            --spec-version 1.6 \
            --dt-compat auto
```

---

## 4. Fusing Runtime TLS/SSH Handshakes & External Scanners (`cbomkit`, `Syft`, `Trivy`)

1. **Static + Live Runtime CBOM Fusion (`Fellegi-Sunter` & `Dempster-Shafer`):**
   ```bash
   ciphermap observe --targets endpoints.txt --output runtime-obs.jsonl
   ciphermap cbom . --offline --include-archives --merge-observations runtime-obs.jsonl --spec-version 1.7 -o fused-cbom.cdx.json
   ```
2. **Import & Diff External CBOMs (`IBM PQCA cbomkit`, `Syft`, `Trivy`, `SandboxAQ`):**
   ```bash
   ciphermap cbom --import-external external-cbomkit.json -o normalized-1.7.cdx.json
   ciphermap cbom --diff baseline-cbom.json,normalized-1.7.cdx.json --fail-on high
   ```
3. **Zero-Backend Auditor HTML Explorer (for 3PAO / PCI-QSA Human Review):**
   ```bash
   ciphermap cbom --view fused-cbom.cdx.json --html cbom-explorer.html
   ```
