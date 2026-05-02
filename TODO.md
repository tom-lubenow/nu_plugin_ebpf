# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-05-02.

This file tracks remaining scope. Detailed historical progress belongs in git
history and release notes, not here.

## Current Project State

- Internal alpha: useful for local development and experiments, but not yet a stable external tool.
- Strongest areas: Nushell-to-eBPF lowering, MIR/LIR/codegen pipeline, typed contexts, maps/globals, many program-family surfaces, callback subprogram lowering, and shared type-inference/verifier/VCC checks.
- Main risks: kernel-version drift, incomplete live attach coverage for newer or riskier program families, and verifier-parity gaps for complex helper/kfunc state.
- Safety policy: keep host integration tests observational where possible; use dry-run for high-risk families; use isolated VMs for `struct_ops`, scheduler, routing, netfilter, or other behavior-changing live loads.

## Near-Term Priority Order

1. Build a verifier differential suite and kernel compatibility matrix so correctness is measured against real kernels.
2. Tighten VCC/verifier parity for helper/kfunc state transitions: provenance, nullability, mutability, ref lifetime, dynptrs, timers, and by-reference stack objects.
3. Continue shrinking raw `helper-call` usage only where an ordinary Nushell form or typed context projection is honest.
4. Extend kernel-version and feature metadata beyond program families into helpers, kfuncs, map kinds, context fields, and loader features.
5. Turn the current internal-alpha surface into a documented external-alpha surface with feature gates, compatibility notes, and safe examples.

## Workstream Division

- Verifier/VCC parity can progress mostly independently from docs and loader work, but it naturally conflicts with helper/kfunc semantic changes because both touch shared state models.
- Program-model/context work should stay mostly linear or be split by disjoint program families; broad registry refactors conflict easily.
- Loader/integration work can run independently if it avoids changing compiler policy tables.
- Documentation/release-readiness work can proceed independently after each compiler checkpoint, but reference docs should be verified against code before committing.
- Good parallel slices: verifier differential harness, kernel compatibility metadata, safe loader fixtures, docs/release cleanup, and one narrow helper/kfunc semantic family at a time.

## Verifier and VCC Parity

- [~] Make VCC a practical pre-kernel verifier for modeled features.
  - Keep type inference, verifier_types, VCC, and backend assumptions in lockstep.
  - Extend pointer-state transitions for helper/kfunc families that mutate provenance, nullability, packet-pointer validity, ref ownership, dynptr state, timer state, and stack-object initialization.
  - Continue modeling branch refinement, range facts, CFG joins, bounded loops, and helper size/bounds constraints.
  - Add BTF-aware validation for remaining map-value fields that carry verifier-sensitive objects such as dynptrs, graph nodes, workqueues, and nested kernel structs.
  - Preserve clear diagnostics when VCC rejects a program that the compiler can describe precisely.

- [~] Add a verifier differential suite.
  - Grow `scripts/verifier_diff.nu` from the initial tagged fixture set and optional-`bpftool` kernel load path into the compatibility matrix driver.
  - Use fixture tiers (`fast`, `btf`, `kernel`, `vm-only`) to keep focused local lanes cheap while preserving heavier BTF/kernel coverage.
  - Track expected accept/reject status, verifier log fragments, required kernel features, and source-verified per-feature minimum kernel versions.
  - Add fixture coverage for maps, helpers, kfuncs, callbacks, context fields, packet bounds, ref lifetimes, dynptrs, timers, and by-reference stack objects.
  - Keep dangerous fixtures dry-run-only or VM-only; the default host lane must remain auto-skip safe.

## Helper, Kfunc, and Callback Semantics

- [~] Keep replacing raw helper usage with honest language forms.
  - Prefer ordinary Nushell syntax and typed context projection over new helper wrappers.
  - Keep `helper-call` and `kfunc-call` as explicit ABI escape hatches for advanced or not-yet-modeled operations.
  - Only add first-class commands when the operation is a real eBPF resource/action without a clear Nushell primitive.
  - Revisit existing first-class commands periodically and remove or narrow any surface that has become redundant.

- [~] Expand typed helper/kfunc semantics where it materially improves safety.
  - Prioritize helpers/kfuncs that affect ownership, lifetime, mutable kernel state, pointer invalidation, by-reference stack objects, or map-value object state.
  - Continue using kernel BTF metadata for unknown kfunc fallback signatures, pointer-space inference, nullable parameters, constant-size parameters, and ref-family heuristics.
  - Keep explicit compiler-side metadata for common helpers/kfuncs where kernel BTF is insufficient or too kernel-version-specific.

## Program Model and Context Support

- [~] Keep the program model authoritative.
  - Program type parsing, section naming, context layout, return aliases, helper policy, kfunc policy, capabilities, and live-attach support should continue to flow from shared program metadata.
  - Avoid reintroducing direct `probe_type` or ad hoc target-string matching in compiler, verifier, or loader paths.
  - Add registry invariants when new program families, context fields, aliases, write surfaces, or helper policies are introduced.

- [~] Broaden program-family support without overfitting on `sched_ext`.
  - Use `sched_ext` as a deep vertical for `struct_ops` and kfunc complexity, but keep packet, socket, cgroup, tracing, iterator, LWT, netfilter, flow dissector, and syscall surfaces moving as separate coverage axes.
  - Keep live `struct_ops:sched_ext_ops` out of normal host tests; use dry-run or VM-only fixtures.
  - Prefer compile/dry-run coverage first for behavior-changing families, then add live attach only when the loader path and test environment are safe.

- [~] Add kernel-version and feature metadata.
  - Keep the program-family and parsed-target compatibility requirement registry authoritative for feature-style requirements. Base program families, BTF tracing/LSM floors, cgroup families, TCX, netfilter links, LWT, struct_ops, sched_ext, XDP multi-buffer sections, cgroup v2, and cgroup UNIX socket-address hooks now carry source-verified minimums where a kernel version is a meaningful claim.
  - Map-kind kernel floors are now source-backed in `MapKind`, aggregated from compiled object map lists, checked before live load, and derived by verifier fixtures for first-class `--kind` arguments plus `tail-call`; helper-only map arguments remain explicit fixture metadata.
  - All modeled helpers now have source-backed `BpfHelper` kernel floors derived from Linux UAPI helper IDs; current verifier `helper-call` and known `kfunc-call` fixtures derive their feature metadata from source text; source-checked fixture kfuncs plus most cpumask/dynptr, task/cgroup/socket/map, iterator, object/list/rbtree, user-copy, crypto, sched_ext, preempt/IRQ, and RCU kfuncs have Rust metadata; and live-load preflight checks helper floors recovered from compiled bytecode plus known-kfunc floors preserved from source lowering. Continue tracking remaining kfuncs, context fields, attach modes, and loader features once each value is source-verified.
  - Kfunc compatibility can now express source-checked upper bounds for removed/renamed kfunc windows; remaining no-hit kfunc signatures are currently res-spin helpers and sched_ext node variants, and should stay unmodeled until found in primary kernel sources.
  - Keep verifier fixture target metadata derived from target strings where possible; use explicit fixture `kernel_features` for context fields, helper-only map arguments, complex first-class helper surfaces the scanner cannot imply, unknown kfuncs, or target-specific requirements the target/source scanner cannot imply.
  - Surface compatibility diagnostics before backend or kernel load when a feature is known to require a newer kernel/config.
  - Document local-kernel detection limits and when the kernel verifier remains authoritative.

## Maps, Globals, and Resource Modeling

- [~] Finish resource-backed map semantics.
  - Keep generic map operations, local storage, socket maps, redirect maps, cgroup arrays, bloom filters, ring buffers, user ring buffers, stack traces, prog arrays, and per-cpu maps aligned across lowering, type checks, VCC, and backend map emission.
  - Keep extending source-level `map-define` only for real map resource metadata. Key/value layouts, natural fixed-record alignment, `--max-entries`, and verifier-managed `bpf_timer`, `bpf_spin_lock`, and top-level `kptr:TYPE` slots are modeled; dynptrs and newer graph/workqueue fields are the next natural BTF-backed validation targets.
  - Add map-in-map support only after inner-map metadata, pinning, loader materialization, and verifier diagnostics are designed.
  - Add arena support only after map-extra, mmap/user-space access, and verifier constraints are modeled.
  - Keep `struct_ops` maps behind the struct_ops object loader rather than generic `map-*` commands.

- [~] Strengthen global/static data support.
  - Broaden fixed-layout globals beyond current scalar/string/binary/list/record cases when the type annotation gives an honest byte layout.
  - Keep source-level fixed-record globals and metadata-built record constants naturally aligned with zero-filled padding and aligned array stride.
  - Keep implicit mutable globals, leading typed `mut`, and explicit `global-*` declarations consistent.
  - Add clearer diagnostics when a Nushell value cannot be represented as fixed-layout eBPF data.

## Language Surface and Control Flow

- [~] Preserve the small Nushell-first surface.
  - Long-term first-class commands should stay limited to real eBPF operations that do not have honest Nushell equivalents.
  - Keep `map-*` and `global-*` resource-oriented, not a template for adding helper wrappers.
  - Prefer improving ordinary Nushell constant evaluation, records, lists, cell paths, assignments, bounded loops, and function specialization.

- [~] Improve control-flow expressiveness safely.
  - Extend bounded loops and list/array iteration only when the verifier-friendly loop shape remains obvious.
  - Keep recursion, unbounded loops, dynamic dispatch, and unbounded allocation out of the eBPF subset.
  - Continue improving early returns, break/continue, option/nothing flow, record/list spread, and user-function specialization where they compile to predictable MIR.

## Loader, Integration, and Safety

- [~] Expand safe live attach coverage.
  - Keep core tracing, packet, socket, cgroup, and TCX live paths healthy.
  - Add live loader support for newer families only with clear safety gates, namespace/VM test plans, and attach-family-specific failure messages.
  - Avoid live host tests for scheduler, routing, netfilter, and other system-behavior-changing families unless isolated.

- [~] Improve the manual and automated integration harnesses.
  - Keep `scripts/manual_integration.nu` bounded, deterministic, and safe by default.
  - Add dry-run smoke fixtures for compile-only families and VM-only lanes for risky live attach families.
  - Track runtime prerequisites explicitly: root/CAP_BPF, kernel BTF, tracefs, bpffs, network namespace setup, cgroup v2, and kernel config dependencies.

## Diagnostics, Docs, and Release Readiness

- [~] Make unsupported-feature diagnostics actionable.
  - Prefer high-level HIR/MIR errors over backend failures.
  - Include the offending surface, the current program family, and a suggested supported rewrite when possible.
  - Keep aliases in diagnostics when users wrote aliases, not only canonical field names.

- [ ] Prepare for external alpha consumption.
  - Define feature gates and compatibility labels for unstable surfaces.
  - Add a concise external quickstart, troubleshooting guide, and safe-example path.
  - Document which program families are live, compile/dry-run only, VM-only, or intentionally unsupported.
  - Add release notes or a changelog so `TODO.md` does not become a historical progress log again.
  - Decide packaging expectations for the plugin binary, Nushell version compatibility, capabilities setup, and kernel feature detection.

## Definition of Complete Enough

- A user can write non-trivial tracing, packet, cgroup/socket, iterator, and selected struct_ops-style programs in ordinary Nushell syntax with minimal escape hatches.
- The compiler rejects unsupported or unsafe constructs before kernel load whenever the reason is knowable locally.
- Compatibility with representative kernels is measured by automated differential tests, not inferred from one development machine.
- Risky live attach families are gated behind explicit flags and documented VM guidance.
- The README, reference docs, examples, and TODO all describe the same current surface.
