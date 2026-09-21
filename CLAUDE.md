# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and contract tables do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. `tc_asn1` is
`no_std` + `alloc` with no feature flags and no dependencies at all — CI
enforces that with `cargo tree` line counts on the `wasm32-unknown-unknown` and
`aarch64-unknown-none` targets. The crate carries no protocol knowledge: OIDs,
extensions and profiles belong to the crates built on it, not here (see the
"Not here" section of the crate docs).

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `cargo package --locked -p <crate>` step in the CI `quality`
job (the only place crates are verified individually), a `cargo tree` line
count in the CI `portable` job, a row in the root `README.md`, and workspace
inheritance for `edition`, `rust-version`, `license`, and `repository`.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`. An additive public API change belongs in the crate
README's contract tables — "Tool types" and "Universal types" in
`tc_asn1/README.md` — and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
