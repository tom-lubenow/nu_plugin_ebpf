# Changelog

This project is still an internal alpha. Until a stable release process exists,
this file records user-facing compiler, loader, diagnostics, compatibility, and
documentation changes that matter to external alpha consumers.

## Unreleased

- Added actionable BTF target diagnostics for invalid `fentry`, `fexit`,
  `fmod_ret`, `tp_btf`, and LSM targets so compile-time errors include the
  modeled target-family rewrite guidance.
- Improved typed global numeric-list initializer diagnostics so bad items name
  the exact initializer path and value kind, for example `initializer[0]`.
- Improved untyped fixed-layout record diagnostics so unsupported nested fields
  name the record path, for example `meta.comm`.
- Improved untyped fixed-array diagnostics so unsupported elements name the
  element index before the underlying layout reason.
- Added verifier coverage for BTF target diagnostic help, typed global
  numeric-list initializer errors, and untyped record field layout rejects.
- Added Rust unit coverage for untyped fixed-array element layout rejects, which
  are currently reached through HIR-level constant materialization rather than
  ordinary source list literals.
- Documented external-alpha packaging, compatibility, troubleshooting, and
  status-driven target selection expectations.
