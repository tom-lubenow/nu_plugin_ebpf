# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-02-14.

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
  - Added shared helper pointer-argument semantics metadata (allowed spaces and size-arg relationships), with verifier_types/VCC enforcement and type-inference pointer-space/size diagnostics (including bounded stack/map access checks) for earlier failures.
  - Extended typed helper semantics coverage to `trace_printk` pointer-space/size/bounds checks through the shared metadata path.
  - Extended typed helper probe-read coverage to include `bpf_probe_read_user` / `bpf_probe_read_kernel` signatures and source-pointer space checks (`User` vs non-`User`) across type inference, verifier_types, and VCC.
  - Added typed helper return modeling (e.g., pointer return for `bpf_map_lookup_elem` helper calls).
  - Typed helper map queue/stack coverage now includes `bpf_map_push_elem` / `bpf_map_pop_elem` / `bpf_map_peek_elem` signatures and pointer-arg semantics (stack-only map handle, stack/map value buffer) with parity tests across type inference, verifier_types, and VCC.
  - Typed helper ringbuf coverage now also includes `bpf_ringbuf_query` signature and map-handle pointer-space checks across type inference, verifier_types, and VCC.
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
  - Ref-lifetime tracking now also covers cpumask kfunc acquire/release (`bpf_cpumask_create` / `bpf_cpumask_acquire` / `bpf_cpumask_release`) with verifier_types/VCC parity tests.
  - Ref-lifetime tracking now also covers object/refcount impl kfuncs (`bpf_obj_new_impl` / `bpf_refcount_acquire_impl` / `bpf_obj_drop_impl`) with verifier_types/VCC parity tests.
  - Ref-lifetime parity now also includes percpu object kfunc ownership (`bpf_percpu_obj_new_impl` / `bpf_percpu_obj_drop_impl`) with verifier_types/VCC regression tests.
  - Ref-lifetime parity now also includes file-reference kfunc ownership (`bpf_get_task_exe_file` / `bpf_put_file`) with verifier_types/VCC regression tests.
  - Built-in typed kfunc signatures now include core kptr container primitives (`bpf_percpu_obj_*_impl`, `bpf_list_{push,pop}_*`, `bpf_rbtree_{add,remove,first}`), with verifier-rewritten `meta/off` arguments modeled as scalar placeholders for ergonomic call sites.
  - Built-in typed kfunc signatures now include task-VMA iterator lifecycle helpers (`bpf_iter_task_vma_new` / `bpf_iter_task_vma_next` / `bpf_iter_task_vma_destroy`) with task-provenance validation on iterator initialization.
  - Built-in typed kfunc signature coverage now includes a broader `bpf_cpumask_*` operation set (logical/inspection/mutation helpers), with shared pointer-family metadata reused by type_infer/verifier/VCC.
  - Built-in typed kfunc coverage now also includes `bpf_cpumask_populate` and `bpf_cpumask_release_dtor`, with cpumask ref-kind and release-lifetime parity across type inference, verifier_types, and VCC.
  - Built-in typed kfunc signature coverage now includes a core `scx_bpf_*` subset (CPU perf/node queries, `cpu_rq`, DSQ management including `dsq_move*`, CPU picking, task-state helpers, task->cgroup lookup, CPU-selection kfuncs, cpumask getter/put helpers, and bstr/events helpers) with shared task/cpumask pointer-family checks.
  - Verifier/VCC kfunc ref-lifetime parity now includes `scx_bpf_*` acquire/release flows for task cgroups and cpumask getter/put pairs (`scx_bpf_task_cgroup`, `scx_bpf_get_*cpumask`, `scx_bpf_put_*cpumask`).
  - Typed kfunc coverage now includes `bpf_rcu_read_lock` / `bpf_rcu_read_unlock`, with verifier_types and VCC parity checks for balanced lock/unlock usage across CFG joins and at function exit.
  - Typed kfunc coverage now includes `bpf_preempt_disable` / `bpf_preempt_enable`, with verifier_types and VCC parity checks for balanced usage across CFG joins and at function exit.
  - Typed kfunc coverage now includes `bpf_local_irq_save` / `bpf_local_irq_restore`, with verifier_types and VCC compile-time parity checks for balanced usage across CFG joins and at function exit.
  - Verifier/VCC now require stack-slot-backed pointers for `bpf_local_irq_save` / `bpf_local_irq_restore` arguments, rejecting context-derived pseudo-stack pointers before kernel load.
  - Typed kfunc coverage now includes `bpf_map_sum_elem_count` with kernel-pointer map-argument checks across type inference, verifier_types, and VCC.
  - Typed kfunc coverage now includes container traversal primitives (`bpf_list_front` / `bpf_list_back` / `bpf_rbtree_root` / `bpf_rbtree_left` / `bpf_rbtree_right`) with shared kernel-pointer argument checks.
  - Verifier/VCC kfunc ref-lifetime parity now tracks acquired reference kind (`task` vs `cgroup`), preserves unknown-kind merges across CFG joins, and rejects mixed-family releases (`bpf_task_release` vs `bpf_cgroup_release`).
  - Verifier/VCC now enforce kernel-pointer address-space requirements for task/cgroup kfunc pointer arguments (e.g., reject stack/map/user pointers for acquire/release/ancestry helpers).
  - Type inference, verifier_types, and VCC now share kfunc pointer-space metadata so non-ref kfuncs (e.g., `bpf_list_*` / `bpf_rbtree_*` / `bpf_path_d_path`) can enforce kernel-pointer argument requirements consistently.
  - Verifier/VCC now enforce task-vs-cgroup provenance on tracked kfunc reference arguments for task/cgroup kfuncs (not just release sites).
  - Verifier/VCC now require non-null checks for tracked ref-kind kfunc arguments (e.g., passing `bpf_task_from_pid` results into `bpf_get_task_exe_file`), and reject use-after-release at those argument sites.
  - Verifier/VCC now preserve pointer/refinement facts through copied and negated branch conditions (including cross-block joins), so guarded kfunc release patterns like `if $task != 0 { ...release... }` verify correctly.
  - Type inference now mirrors kernel-pointer address-space checks for task/cgroup kfunc pointer arguments so these failures are reported earlier.
  - Shared kfunc ref-family metadata is now centralized in `instruction.rs` and consumed by type inference, verifier_types, and VCC to keep task/cgroup semantics in sync.
  - Verifier parity now enforces the generic helper argument cap (`<= 5` args) for unknown helper IDs in both verifier_types and VCC.
  - Verifier parity now enforces the MIR function parameter cap (`<= 5`) that backend BPF subfunction lowering requires, with verifier_types/VCC regression tests.
  - Verifier parity now enforces `CallSubfn` argument limits (`<= 5`) before MIR->LIR lowering, with verifier_types/VCC regression tests.
  - Shared helper semantics now reject map-value pointers in helper map-handle argument positions (e.g., map args to map/ringbuf/perf/tail-call/get_stackid helpers), with parity tests across verifier_types and VCC.
  - Typed helper coverage now includes `bpf_kptr_xchg` (helper ID `194`) with null-const arg handling, pointer-space checks, and kernel-pointer return modeling across type inference, verifier_types, and VCC.
  - `bpf_kptr_xchg` semantics now transfer tracked kfunc-ref ownership from arg1 to the helper return value, invalidating the source ref and enabling verifier-safe release of the swapped-out reference.
  - `bpf_kptr_xchg` arg0 parity now enforces map-pointer destination slots (`[Map]`), rejecting stack-pointer destinations in verifier_types/VCC/type inference.
  - Helper ref-lifetime parity now covers socket helpers (`bpf_sk_lookup_tcp` / `bpf_sk_lookup_udp` / `bpf_sk_release`), including kernel-pointer arg checks, tracked socket ownership, null-guarded release, cross-family mismatch diagnostics, and leak checks in verifier_types/VCC.
  - Typed helper socket coverage now also includes `bpf_skc_lookup_tcp` with socket-ref acquire/release lifetime parity across type inference, verifier_types, and VCC.
  - Typed helper socket coverage now also includes `bpf_get_listener_sock` pointer-space/return modeling across type inference, verifier_types, and VCC.
  - Typed helper socket coverage now also includes `bpf_tcp_check_syncookie` with kernel-pointer/size-arg semantics and socket ref-family checks on tracked `sk` refs across type inference, verifier_types, and VCC.
  - Typed helper socket coverage now also includes `bpf_tcp_gen_syncookie` and `bpf_sk_assign`, including kernel-pointer/size-arg checks, nullable `sk` handling for `sk_assign`, and socket ref-family checks on tracked `sk` refs across type inference, verifier_types, and VCC.
  - Typed helper file/socket bridge coverage now also includes `bpf_sock_from_file`, including kernel-pointer arg checks, kernel-pointer return modeling, and tracked file-ref provenance checks across verifier_types and VCC.
  - Typed helper task register coverage now also includes `bpf_task_pt_regs`, including kernel-pointer arg checks, kernel-pointer return modeling, and task ref-family checks across type inference, verifier_types, and VCC.
  - Typed helper socket-storage coverage now also includes `bpf_sk_storage_get` / `bpf_sk_storage_delete`, including map/socket pointer-space checks, null-init support for `sk_storage_get`, and socket ref-family checks on tracked `sk` refs across type inference, verifier_types, and VCC.
  - Typed helper task-storage coverage now also includes `bpf_task_storage_get` / `bpf_task_storage_delete`, including map/task pointer-space checks, null-init support for `task_storage_get`, and task ref-family checks on tracked `task` refs across type inference, verifier_types, and VCC.
  - Typed helper inode-storage coverage now also includes `bpf_inode_storage_get` / `bpf_inode_storage_delete`, including map/inode pointer-space checks, null-init support for `inode_storage_get`, and inode ref-family checks on tracked refs across verifier_types and VCC.
  - Typed helper socket coverage now also includes `bpf_sk_fullsock` / `bpf_tcp_sock` / `bpf_skc_to_tcp_sock` / `bpf_skc_to_tcp6_sock` / `bpf_skc_to_tcp_timewait_sock` / `bpf_skc_to_tcp_request_sock` / `bpf_skc_to_udp6_sock` / `bpf_skc_to_unix_sock` pointer-space and nullable kernel-pointer return modeling across type inference, verifier_types, and VCC.
  - Verifier/VCC helper-arg parity now enforces socket ref-family provenance for tracked kernel refs passed to socket-pointer helpers (`bpf_get_listener_sock` / `bpf_sk_fullsock` / `bpf_tcp_sock`), rejecting mixed-family refs (e.g., task ref args).
  - VCC now aligns typed pointer nullability with verifier_types (`Map`/`Kernel`/`User` pointers are `MaybeNull` until guarded), including parity tests for load/read_str/helper flows that require explicit null checks.
  - VCC helper pointer-space checks now resolve `Unknown` vreg pointer spaces via effective MIR address-space fallback, preventing helper-space-rule bypasses for typed stack pointers.
  - VCC now propagates map-value bounds from built-in map semantics and pointee types, including pointer-arithmetic/load/store bounds checks for map-value pointers.
  - VCC now aligns direct memory access rules with verifier expectations by rejecting raw `load`/`store` on non stack/map pointer spaces.
  - Remaining: extend pointer-state transitions to broader helper/kfunc families (provenance/nullability/mutability/ref-lifetime) with kernel-verifier-level fidelity.

## Research-backed compiler core work

- [x] Fix SSA destruction correctness with parallel-copy lowering.
  - Replaced naive phi elimination with per-edge parallel-copy sets and cycle-safe sequentialization.
  - Added regression tests for lost-copy cases (multi-phi joins and loop-header swaps).
  - Critical edges are now split so copies execute only on the intended control-flow edge.

- [x] Replace `ssa::rename_uses` exhaustive reconstruction with operand-mapper APIs.
  - Added `MirValue::visit_vregs_mut` / `MirValue::map_vregs` and `MirInst::visit_uses_mut` / `MirInst::map_uses` helpers.
  - Switched SSA rename and copy propagation to these helpers so new MIR operand sites are centralized in one API.

- [x] Unify duplicated CFG/dominance/liveness analysis infrastructure.
  - Extracted shared generic CFG/liveness/loop analysis in `cfg.rs` behind `CfgInst`/`CfgBlock`/`CfgFunction` adapters (`AnalysisCfg`, `BlockLiveness`, `GenericLoopInfo`).
  - `graph_coloring.rs` now reuses this shared analysis instead of private `AllocCfg`/`AllocLiveness`, and MIR `CFG`/`LivenessInfo` now consume the same core idom/liveness algorithms.

- [x] Upgrade constant propagation from local folding to SSA-aware SCCP.
  - Constant propagation now tracks per-vreg lattice values together with executable CFG edges/reachable blocks.
  - Phi-derived constants are folded, constant branches are simplified, and unreachable blocks/phi inputs are pruned in one analysis/rewrite pass.

- [x] Make pass analysis freshness explicit.
  - PassManager now rebuilds CFG before each pass invocation (not just per-iteration), so CFG-sensitive passes do not consume stale analyses after earlier CFG-mutating passes.
  - Added a regression test (`test_pass_manager_rebuilds_cfg_between_passes`) that fails under stale-CFG behavior when iterations are capped.

- [x] Add rematerialization for cheap spilled values.
  - Spilled vregs with pure constant/stack-address definitions are now rematerialized at use sites instead of always reloading from spill slots.
  - Codegen now writes non-rematerialized spilled defs back to stack consistently, with tests covering both remat and non-remat spill paths.

- [x] Move block lookup from linear search to O(1) access.
  - `MirFunction`/`LirFunction` now do index-first block lookup by `BlockId` (`id -> blocks[id]`) and only fall back when block IDs are no longer index-stable.
  - Added regression tests for the fallback path after simulated block removal/reordering.

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
  - Added lifetime/lock-depth verifier parity for `bpf_res_spin_lock`/`unlock` and `bpf_res_spin_lock_irqsave`/`unlock_irqrestore`, including branch-join handling and exit checks.
  - Added pointer-space enforcement for `bpf_res_spin_*` arguments (`arg0` kernel lock pointer, `irqsave/irqrestore arg1` stack flags pointer) across type inference, verifier_types, and VCC.
  - Added stack-slot identity tracking for `bpf_local_irq_save`/`restore` and `bpf_res_spin_*_irq*` so restore/irqrestore must match the saved flags slot (including branch-join state merges).
  - Added stack-slot identity and lifetime modeling for `bpf_iter_task_vma_new`/`next`/`destroy`: iterator pointers must be concrete stack-slot pointers, `next`/`destroy` require a matching `new` on all reachable paths (including mixed-join rejection), and unreleased iterators are rejected at exit.
  - Tightened stack-argument semantics so stack-required kfunc args (`local_irq*`, `res_spin_*_irq*`, `iter_task_vma*`) must be slot base pointers (offset 0), not interior stack addresses.
  - Remaining: expand signature coverage and pointer/ref-lifetime semantics from richer BTF metadata.
  - Remaining: model richer by-reference out-parameter semantics (aliasing/copy semantics and typed stack object identity) for additional kfunc families beyond current lock/irq patterns.

- [ ] Improve control-flow expressiveness safely.
  - Keep bounded-loop guarantees while supporting more realistic higher-level control patterns.
  - Ensure CFG lowering remains verifier-friendly with predictable complexity limits.

- [ ] Support global/static data sections.
  - Add language and backend support for `.rodata`, `.data`, and `.bss` style globals where valid.
  - Ensure symbol/relocation handling is deterministic and test-covered.

## Ergonomics and quality

- [~] Improve unsupported-feature diagnostics.
  - Replace generic "unsupported" failures with actionable messages that include rewrites/workarounds.
  - Emit diagnostics at the highest possible level (HIR/MIR) before backend failure.
  - Recent progress: unknown-kfunc diagnostics now indicate when the symbol exists in kernel BTF but lacks a compiler-side typed signature.

- [ ] Build a compatibility test matrix.
  - Add automated tests that exercise compilation and loading across representative kernel versions/configs.
  - Include differential checks against verifier behavior and manual attach smoke tests.

- [ ] Add end-to-end non-tracing fixtures.
  - Create integration fixtures that validate map-heavy, helper-heavy, and control-flow-heavy programs.
  - Keep fixtures small and verifier-focused to catch regressions quickly.

- [ ] Stabilize language surface and feature gating.
  - Define capability-based feature flags so unsupported constructs fail predictably.
  - Version language features explicitly to avoid silent behavior drift.
