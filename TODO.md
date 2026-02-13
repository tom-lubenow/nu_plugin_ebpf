# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-02-13.

## Current compiler gaps

- [~] Complete the VCC verifier model.
  - VCC is a mandatory gate, but the model is still incomplete versus kernel verifier behavior for broader program classes.
  - Expand tracked state beyond current pointer/stack/map/range model and tighten parity tests against real verifier outcomes.
  - Recent progress: VCC verification runs as CFG dataflow over reachable blocks (with state joins/widening), includes nullable-pointer branch refinement with impossible-branch pruning, and applies typed helper argument/return checks plus helper-specific pointer-space and size/bounds checks for core helpers.

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
  - Added shared helper pointer-argument semantics metadata (allowed spaces and size-arg relationships) and wired both verifier_types and VCC to consume it.
  - Extended typed helper semantics coverage to `trace_printk` pointer-space/size/bounds checks through the shared metadata path.
  - Added typed helper return modeling (e.g., pointer return for `bpf_map_lookup_elem` helper calls).
  - Added helper-side pointer-space and range-aware size/bounds checks in the verifier, with matching VCC checks for map ops, probe-read variants, ringbuf output, perf-event output, `get_stackid`, `tail_call`, and `get_current_comm`.
  - Added initial helper ref-lifetime/provenance tracking in both verifier and VCC for ringbuf reserve/submit/discard (including branch-aware null-check refinement, leak detection at function exit, and pointer invalidation after release).
  - VCC now tracks nullable pointer returns for map/ringbuf helper results and rejects dereference paths that skip a null check.
  - VCC now refines scalar compare guards across branches and applies range-aware dynamic helper size checks (e.g. variable-size `get_current_comm` bounds validation).
  - VCC now retains scalar `!= const` facts across guarded branches, pruning impossible follow-up `== const` paths.
  - VCC now refines scalar-vs-scalar comparison guards across branches (including vreg bounds), enabling verifier-safe pointer arithmetic in guarded paths.
  - VCC now enforces `read_str` source pointer-space parity (`user_space=true` requires User pointers; kernel mode rejects User pointers).
  - VCC now models scalar `div`/`mod` ranges (including branch-derived `!= 0` divisor facts), reducing false `UnknownOffset` failures in guarded pointer arithmetic.
  - VCC now models non-negative scalar `and`/`or`/`xor`/`shl`/`shr` ranges, improving bounds precision for computed pointer offsets.
  - Added MIR-level parity tests for stack pointer non-null assumptions and stack load/offset bounds (direct add, mul, shift, and bitwise-derived offsets).
  - VCC now enforces helper `size > 0` constraints for scalar vreg size args (not just literal immediates), matching verifier-side range behavior.
  - Verifier parity now enforces scalar-only indices for `MirInst::TailCall` terminators, with matching verifier_types/VCC regression tests.
  - Verifier parity now enforces `MirInst::TailCall` map-kind requirements (`ProgArray` only) before backend codegen, with matching verifier_types/VCC regression tests.
  - Verifier parity now enforces generic map-operation kind constraints (reject unsupported kinds; reject `MapDelete` on array/per-cpu-array kinds) before backend codegen, with matching verifier_types/VCC regression tests.
  - Verifier parity now enforces `MapUpdate` flags range checks (`<= i32::MAX`) before backend codegen, with matching verifier_types/VCC regression tests.
  - Verifier parity now enforces generic map key/value scalar-operand size constraints (`<= 8` bytes unless passed as pointers), matching backend `map_operand_layout` behavior with verifier_types/VCC regression tests.
  - Verifier parity now enforces generic map layout consistency across operations (kind/key-size/value-size conflict detection), matching backend `register_generic_map_spec` behavior with verifier_types/VCC regression tests.
  - Verifier parity now enforces built-in counter-map kind restrictions and conflicts (`counters`/`str_counters` require `Hash` or `PerCpuHash`, with no mixed-kind usage).
  - Verifier parity now enforces string-counter key shape requirements (stack/map pointer with in-bounds 16-byte access) instead of allowing scalar keys.
  - Verifier parity now models `bpf_task_acquire`/`bpf_task_release` reference lifetimes (tracked refs, null-branch drop, double-release/leak checks, and pointer invalidation after release).
  - VCC parity now mirrors `bpf_task_acquire`/`bpf_task_release` reference lifetimes (tracked refs, null-branch drop, leak checks, and pointer invalidation after release).
  - Ref-lifetime tracking now also covers common task/cgroup kfunc acquire/release families (`bpf_task_from_pid`, `bpf_task_from_vpid`, `bpf_task_get_cgroup1`, `bpf_cgroup_acquire`, `bpf_cgroup_from_id` with corresponding release checks).
  - Verifier parity now enforces the generic helper argument cap (`<= 5` args) for unknown helper IDs in both verifier_types and VCC.
  - Verifier parity now enforces the MIR function parameter cap (`<= 5`) that backend BPF subfunction lowering requires, with verifier_types/VCC regression tests.
  - Verifier parity now enforces `CallSubfn` argument limits (`<= 5`) before MIR->LIR lowering, with verifier_types/VCC regression tests.
  - Shared helper semantics now reject map-value pointers in helper map-handle argument positions (e.g., map args to map/ringbuf/perf/tail-call/get_stackid helpers), with parity tests across verifier_types and VCC.
  - VCC now aligns typed pointer nullability with verifier_types (`Map`/`Kernel`/`User` pointers are `MaybeNull` until guarded), including parity tests for load/read_str/helper flows that require explicit null checks.
  - VCC now propagates map-value bounds from built-in map semantics and pointee types, including pointer-arithmetic/load/store bounds checks for map-value pointers.
  - VCC now aligns direct memory access rules with verifier expectations by rejecting raw `load`/`store` on non stack/map pointer spaces.
  - Remaining: extend pointer-state transitions to broader helper/kfunc families (provenance/nullability/mutability/ref-lifetime) with kernel-verifier-level fidelity.

## Research-backed compiler core work

- [x] Fix SSA destruction correctness with parallel-copy lowering.
  - Replaced naive phi elimination with per-edge parallel-copy sets and cycle-safe sequentialization.
  - Added regression tests for lost-copy cases (multi-phi joins and loop-header swaps).
  - Critical edges are now split so copies execute only on the intended control-flow edge.

- [ ] Replace `ssa::rename_uses` exhaustive reconstruction with operand-mapper APIs.
  - Add `MirInst` operand walk/mutation helpers (for vreg uses and `MirValue` operands).
  - Reuse these helpers in SSA rename and follow-on passes to reduce maintenance hazards when instructions evolve.

- [ ] Unify duplicated CFG/dominance/liveness analysis infrastructure.
  - Extract shared algorithms from `cfg.rs` and `graph_coloring.rs` behind small traits/adapters.
  - Keep a single implementation of immediate-dominator and core liveness dataflow logic.

- [ ] Upgrade constant propagation from local folding to SSA-aware SCCP.
  - Track constant lattice values and CFG reachability together.
  - Fold phi-driven constants and prune unreachable edges in one analysis.

- [ ] Make pass analysis freshness explicit.
  - Add invalidation metadata (or per-pass rebuilds) so CFG-sensitive passes do not consume stale analyses after CFG mutations.

- [ ] Add rematerialization for cheap spilled values.
  - Recompute simple constants/expressions at use sites instead of always using stack spill slots.

- [ ] Move block lookup from linear search to O(1) access.
  - If IDs remain index-stable, index blocks directly; otherwise maintain an explicit ID-to-index map.

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

- [~] Add kfunc and richer BTF-driven typing support.
  - Added typed `CallKfunc` MIR/LIR support with backend lowering to `BPF_PSEUDO_KFUNC_CALL`.
  - Added optional explicit kfunc BTF IDs plus kernel-BTF name lookup fallback in codegen.
  - Added initial typed kfunc signatures wired through type inference, verifier_types, and VCC.
  - Expanded built-in kfunc signature coverage for common task/cgroup kfunc families (`*_from_pid`, `*_from_id`, acquire/release, ancestry checks).
  - Added user-facing `kfunc-call` closure helper with literal-name lowering and optional `--btf-id`.
  - Remaining: expand signature coverage and pointer/ref-lifetime semantics from richer BTF metadata.

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
