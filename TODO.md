# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-02-12.

## Current compiler gaps

- [~] Complete the VCC verifier model.
  - VCC is a mandatory gate, but the model is still incomplete versus kernel verifier behavior for broader program classes.
  - Expand tracked state beyond current pointer/stack/map/range model and tighten parity tests against real verifier outcomes.

- [x] Implement tail calls end-to-end.
  - Implemented bytecode lowering to `bpf_tail_call` and failure fallback termination.
  - Added `ProgArray` map emission and relocation plumbing, with positive/negative compiler tests.

- [ ] Implement generic map operations end-to-end.
  - `MapLookup` / `MapDelete` are still rejected in codegen.
  - Ensure lookup/update/delete work for all supported key/value type layouts with precise nullability and bounds checks.

- [ ] Make map kind a first-class backend concern.
  - Lowering carries `MapKind`, but map emission/codegen paths are still biased toward tracing maps.
  - Use `MapKind` to drive ELF map defs, helper usage, and loader behavior consistently.

- [ ] Replace opaque helper handling with typed helper semantics.
  - `CallHelper` remains too generic for robust verifier modeling and diagnostics.
  - Introduce typed helper signatures (arg constraints, return types, pointer provenance, mutability effects).

## Roadmap to a general-purpose eBPF language

- [ ] Expand program type support beyond probes.
  - Add program-type-aware compile targets (section naming, context type, helper set, attach/load path).
  - Keep tracing as one target among many instead of the default architecture.

- [ ] Generalize context modeling by program type.
  - Replace tracing-centric context fields with per-program typed context schemas.
  - Make illegal context access fail early in HIR/MIR type checking.

- [ ] Expand map support to the broader eBPF map ecosystem.
  - Add missing map definitions and loader plumbing for commonly used map families.
  - Validate map capability compatibility per program type and kernel version.

- [ ] Add kfunc and richer BTF-driven typing support.
  - Model typed kfunc calls similarly to helpers, with verifier-aware pointer/state transitions.
  - Improve BTF usage so type information can drive safer IR generation and diagnostics.

- [ ] Improve control-flow expressiveness safely.
  - Keep bounded-loop guarantees while supporting more realistic higher-level control patterns.
  - Ensure CFG lowering remains verifier-friendly with predictable complexity limits.

- [ ] Support global/static data sections.
  - Add language and backend support for `.rodata`, `.data`, and `.bss` style globals where valid.
  - Ensure symbol/relocation handling is deterministic and test-covered.

## Ergonomics and quality

- [ ] Improve unsupported-feature diagnostics.
  - Replace generic "unsupported" failures with actionable messages that include rewrites/workarounds.
  - Emit diagnostics at the highest possible level (HIR/MIR) before backend failure.

- [ ] Build a compatibility test matrix.
  - Add automated tests that exercise compilation and loading across representative kernel versions/configs.
  - Include differential checks against verifier behavior and manual attach smoke tests.

- [ ] Add end-to-end non-tracing fixtures.
  - Create integration fixtures that validate map-heavy, helper-heavy, and control-flow-heavy programs.
  - Keep fixtures small and verifier-focused to catch regressions quickly.

- [ ] Stabilize language surface and feature gating.
  - Define capability-based feature flags so unsupported constructs fail predictably.
  - Version language features explicitly to avoid silent behavior drift.
