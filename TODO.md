# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-02-12.

## Current compiler gaps

- [~] Complete the VCC verifier model.
  - VCC is a mandatory gate, but the model is still incomplete versus kernel verifier behavior for broader program classes.
  - Expand tracked state beyond current pointer/stack/map/range model and tighten parity tests against real verifier outcomes.
  - Recent progress: VCC verification now runs as CFG dataflow over reachable blocks (with state joins/widening), and verifier/VCC both apply typed helper argument/return checks plus helper-specific pointer-space and size/bounds checks for core helpers.

- [x] Implement tail calls end-to-end.
  - Implemented bytecode lowering to `bpf_tail_call` and failure fallback termination.
  - Added `ProgArray` map emission and relocation plumbing, with positive/negative compiler tests.

- [x] Implement generic map operations end-to-end.
  - Added `MapLookup` / `MapUpdate` / `MapDelete` codegen for generic map ops, while preserving the specialized `count` lowering path.
  - Added generic map ELF emission + relocations from map-op usage (including key/value size inference and map-kind-aware defs for hash/array/per-cpu maps).
  - Expanded type/VCC checks to allow scalar or stack/map-pointer operands for generic map keys/values, with backend guards for unsupported map-kind helper usage.

- [x] Make map kind a first-class backend concern.
  - Counter/string-counter map emission now preserves inferred `MapKind` (hash vs per-cpu hash) and rejects invalid kind usage at codegen time.
  - Backend map defs are kind-aware for built-in and generic map paths, instead of only name-driven defaults.
  - Loader counter readers now support both hash and per-cpu hash map types, aggregating per-cpu values consistently.

- [~] Replace opaque helper handling with typed helper semantics.
  - Added shared helper signatures for known helper IDs and wired signature-aware arg-count/type checks through type inference, VCC, and codegen.
  - Added typed helper return modeling (e.g., pointer return for `bpf_map_lookup_elem` helper calls).
  - Added helper-side pointer-space and range-aware size/bounds checks in the verifier, with matching VCC checks for map ops, probe-read variants, ringbuf output, perf-event output, and `get_current_comm`.
  - Added initial helper ref-lifetime/provenance tracking in the verifier for ringbuf reserve/submit/discard (including leak detection at function exit and pointer invalidation after release), plus VCC ringbuf-record pointer provenance checks for submit/discard.
  - Remaining: extend pointer-state transitions to broader helper/kfunc families (provenance/nullability/mutability/ref-lifetime) with kernel-verifier-level fidelity.

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
