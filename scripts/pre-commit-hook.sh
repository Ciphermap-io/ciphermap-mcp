#!/bin/sh
# pre-commit (pre-commit.com) entry point — identical contract to `ciphermap hook install`.

if ! command -v ciphermap >/dev/null 2>&1; then
    echo "❌ CipherMap is not installed on PATH, so the offline PQC gate cannot run."
    echo "   Claim the signed offline CLI (.zip) at:"
    echo "     https://www.ciphermap.io/eval-pack"
    echo "   Or remove the ciphermap hook from .pre-commit-config.yaml."
    exit 1
fi

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    exec ciphermap scan . --staged --offline --fail-on high --quiet
fi
exec ciphermap scan . --offline --fail-on high --quiet
