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
- Improved annotated mutable record global diagnostics so nested initializer
  extra fields and type mismatches name paths such as `stats.extra` and
  `stats.hits`.
- Improved typed `global-define` record initializer diagnostics so nested
  unexpected fields name the full path, for example `inner.extra`.
- Improved typed `global-define` nested record type-spec diagnostics so malformed
  fields, invalid length/capacity specs, and unsupported field specs name paths
  such as `inner.bad` or `items`.
- Improved typed `global-define` record/array type-spec candidate diagnostics so
  unbalanced braces report brace errors instead of generic unsupported-type
  fallbacks.
- Improved typed `global-define` array initializer diagnostics so top-level
  bad items use `initializer[0]` style paths instead of record-field wording.
- Added verifier coverage for BTF target diagnostic help, typed global
  numeric-list initializer errors, untyped record field layout rejects, and
  typed `global-define` array item, nested annotated mutable record, typed
  `global-define` extra-field, and nested record type-spec rejects.
- Added Rust unit coverage for untyped fixed-array element layout rejects, which
  are currently reached through HIR-level constant materialization rather than
  ordinary source list literals.
- Added Rust unit coverage for nested annotated mutable record initializer type
  mismatch paths that Nushell source parsing rejects before verifier fixtures
  can reach plugin lowering.
- Documented external-alpha packaging, compatibility, troubleshooting, and
  status-driven target selection expectations.
