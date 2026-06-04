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
- Added verifier coverage for BTF target diagnostic help and typed global
  numeric-list initializer errors.
- Documented external-alpha packaging, compatibility, troubleshooting, and
  status-driven target selection expectations.
