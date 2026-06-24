# ns.lol — Backlog

> Known tech debt, pending work, and deferred improvements. Priority: P0 (blocking) → P4 (nice-to-have).

## P2 — No Version Tracking

No `NS_VERSION` constant, no CHANGELOG, no release tags. Makes it hard to track what's deployed.

## P3 — Probe User-Agent Hardcoded to 1.0

`probe/server.js` sends a hardcoded User-Agent with version `1.0` regardless of actual version.

## P4 — No MCP Server

yoke has an MCP server on npm. ns.lol could benefit from one (DNS lookups are a natural MCP tool). Lower priority since yoke's MCP already covers domain intelligence.
