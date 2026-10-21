# ADR-0038: The web UI is native HTML, CSS and JavaScript, multi-page with interactive islands

**Status:** Accepted (2026-10-21, Hilmi: "Ya, native" and "yupss" to the multi-page with islands design). Applies to the controller web UI of the SDN spec (#176, SDN-28 #204) and the unified management spec (#224). Builds on ADR-0026 (the controller serves the web UI) and ADR-0031 (the public intent API).

## Context

The controller serves one web UI for everything Ranz manages: VRFs, networks, nodes and their capabilities, users and groups, policy, listeners, bridges, revisions with diff and rollback, `ranz explain`, the audit log and live telemetry, in English and Indonesian (SDN-60). The SDN spec fixes one rule already: the UI uses only the public API, so everything a user can click can also be scripted (story 88).

The usual default for such a UI is TypeScript with a single-page framework (React, Svelte and the like). That needs a build step, a Node toolchain in CI and an npm dependency tree in a proprietary product. The dependency rule of this project is native first, then an established library, own code last. Browsers now ship what an admin UI needs: ES modules, Web Components, `fetch`, `EventSource` and `WebSocket`, `<dialog>` and `<template>`, modern CSS, cross-document View Transitions and Speculation Rules.

## Decision

1. **Native HTML, CSS and JavaScript, no build step, no framework, no npm.** Modules load as `<script type="module">`. Shared parts (navigation, sign-in state, tables, forms, dialogs, live event views) are Web Components (`customElements`).
2. **Type checking without TypeScript output.** Scripts carry JSDoc types and `// @ts-check`; CI runs `tsc --noEmit` over them as a development check only. Nothing is compiled and nothing extra ships.
3. **Multi-page with interactive islands.** Each area is its own page with its own URL (`/networks`, `/users`, `/policies`, `/audit`, ...), so the back button, bookmarks and reload work without a client router. Inside a page, the heavy parts behave like a small application and update without a reload: the topology view, the explain trace, the policy editor and live telemetry, through `fetch`, `EventSource` and `WebSocket` against the public API.
4. **One routing system.** Routes exist only as pages served by the controller. State inside a page (open tab, filter, selected VRF) lives in the query string (`?vrf=corp&tab=routes`) and is updated with `history.replaceState`, so links stay shareable. There is no client-side router.
5. **Smooth navigation with native features.** Cross-document View Transitions (`@view-transition { navigation: auto; }`) animate page changes, and Speculation Rules prefetch or prerender a page on hover. Browsers without them fall back to plain navigation.
6. **Served from the controller binary.** The files are embedded with Go `embed` and served on 443 next to the API (ALPN `h2` and `http/1.1`, ADR-0035), with a strict Content Security Policy: no inline scripts or styles, `script-src 'self'`. Port 80 only redirects to HTTPS and answers ACME HTTP-01 (ADR-0020).
7. **Strings from one table per language.** English and Indonesian strings live in one file per language; a missing key fails a CI check (SDN-60).

## Consequences

- No Node toolchain, bundler or npm lock file in the repository or the release; the UI has no third-party runtime code to patch.
- Every UI action is a public API call, which the SDN-28 acceptance criteria already require; the UI is a client of the API like `ranz`.
- Components are written by hand on the Web Components API, so there is more own code than with a framework. This is accepted under the dependency rule; a small established library can be vendored later as a single ES module if a component proves too costly to write, recorded as an amendment.
- The UI is tested in CI against the controller and the node simulator with a headless browser.
