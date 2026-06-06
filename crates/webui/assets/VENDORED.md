# Vendored Web UI assets (KOV-29)

These third-party front-end assets are **vendored on purpose** (not fetched from a
CDN at runtime): the Web UI is served on loopback while displaying secrets, so the
browser must never reach out to a third party for code, and `kovra ui` must work
fully offline. Each file is pinned to an exact version and embedded into the
`kovra-webui` binary via `include_str!` (see `src/assets.rs`) — no Node/npm/Vite
build, single binary, Docker (I9) and loopback (I10) properties unchanged.

> Updating an asset is a security-relevant change: bump the version, re-record the
> SHA-256 below, and review the diff like any other dependency bump.

## Tabulator — interactive data grid

- Package: `tabulator-tables`
- Version: **6.3.1**
- Source: `https://cdn.jsdelivr.net/npm/tabulator-tables@6.3.1/dist/`
- License: MIT

| File | SHA-256 | SRI |
|------|---------|-----|
| `tabulator/tabulator.min.js`  | `e952272c3b2afa4ebb60cef5db8cbe9cbaabaa52b50c3cd3d22993ca5215a6ff` | `sha256-6VInLDsq+k67YM7124y+nLqrqlK1DDzT0imTylIVpv8=` |
| `tabulator/tabulator.min.css` | `a46d8051944c745cae8a7976b4fb9d93d894d20876a4521cc4f6f035cfef52ea` | `sha256-pG2AUZRMdFyuinl2tPudk9iU0gh2pFIcxPbwNc/vUuo=` |

## Brand fonts — Sora + Inter (latin subset, woff2)

Vendored offline so the loopback Web UI never reaches a CDN for a font. Only the
weights the theme actually uses are shipped: **Sora 600** (display/wordmark) and
**Inter 400/500/600** (UI/body). Files are the `latin` subset taken from the
`@fontsource` packages (the same upstream Google Fonts faces, repackaged one
weight+subset per file).

- Packages: `@fontsource/sora`, `@fontsource/inter`
- Source: `https://cdn.jsdelivr.net/npm/@fontsource/<family>/files/`
- Licenses: Sora — OFL-1.1; Inter — OFL-1.1

| File | SHA-256 |
|------|---------|
| `fonts/sora-latin-600-normal.woff2`  | `fa9ab76f30510ad92153c6d6d72d0508884b85e9f0148abdfa963231b2a4845a` |
| `fonts/inter-latin-400-normal.woff2` | `8909904ab6c872eb994093482a88a28eca2cd95912d7b6fecd72103b0dc07edc` |
| `fonts/inter-latin-500-normal.woff2` | `f3779f1efccc4bdcdf9c0a02ab95bf6bd092ed09c48c08cedc725889edd1d19f` |
| `fonts/inter-latin-600-normal.woff2` | `f9a06e79cd3a2a20951c0f0e28f66dd0e6d3fda73911d640a2125c8fcb78f21a` |

## Brand icon — cobra / keyhole emblem

The sidebar logo + favicon. Downscaled to ~256px from the 1024² master that
lives in `docs/design/kovra-icon.png` (kept out of the binary); regenerate with
`sips -Z 256 -s format png docs/design/kovra-icon.png --out crates/webui/assets/kovra-icon.png`.

- Source: first-party AI-generated brand emblem (see `docs/design/brand.md`)

| File | SHA-256 |
|------|---------|
| `kovra-icon.png` | `49cbc846123b89d140b390c397a718237846029201cb0cb5d704c33ea2f7ea3e` |

## First-party app assets (not vendored — written here)

- `app.js`  — the Web UI client (Tabulator grid + governed reveal + management
  actions). Hand-written, no framework, no build.
- `app.css` — the Web UI theme (brand design system — `docs/design/brand.md`).
