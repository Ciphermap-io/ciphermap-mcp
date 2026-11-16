# Zero-dependency MCP stdio protocol & onboarding container for CipherMap.
# Contains ONLY the open-source MIT Node.js MCP launcher & 11-tool JSON Schema manifest
# (zero proprietary engine binaries; full local scans delegate to signed native CLI).
FROM node:22-alpine

WORKDIR /app
COPY packages/ciphermap-mcp/package.json ./packages/ciphermap-mcp/package.json
COPY packages/ciphermap-mcp/tool-manifest.json ./packages/ciphermap-mcp/tool-manifest.json
COPY packages/ciphermap-mcp/bin/ciphermap-mcp.js ./packages/ciphermap-mcp/bin/ciphermap-mcp.js
COPY LICENSE ./LICENSE

USER node
ENTRYPOINT ["node", "/app/packages/ciphermap-mcp/bin/ciphermap-mcp.js"]
