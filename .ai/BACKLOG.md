# ns.lol — Backlog

> Known tech debt, pending work, and deferred improvements. Priority: P0 (blocking) → P4 (nice-to-have).

## P1 — No Tests

Zero test files. No unit tests, no integration tests. The codebase is ~4,229 lines with no automated verification. Priority because DNS parsing edge cases are subtle and breakage is silent.

## P1 — IIJ Duplicate Resolver

IIJ appears twice in the DoH resolver list (`src/dns.ts`). Wastes a query slot and skews results. Simple fix: remove the duplicate.

## P2 — No CLI

certs and yoke both have Go CLIs distributed via Homebrew tap. ns.lol has no CLI yet. Would follow the same pattern: Go binary, goreleaser, `yokedotlol/tap/ns`.

## P2 — No Version Tracking

No `NS_VERSION` constant, no CHANGELOG, no release tags. Makes it hard to track what's deployed.

## P3 — Probe User-Agent Hardcoded to 1.0

`probe/server.js` sends a hardcoded User-Agent with version `1.0` regardless of actual version.

## P4 — No MCP Server

yoke has an MCP server on npm. ns.lol could benefit from one (DNS lookups are a natural MCP tool). Lower priority since yoke's MCP already covers domain intelligence.
