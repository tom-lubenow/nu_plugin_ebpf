# TODO

Status legend: `[x]` done, `[~]` in progress, `[ ]` todo.
Last updated: 2026-05-31.

This file tracks remaining scope. Detailed historical progress belongs in git
history and release notes, not here.

## Current Project State

- Internal alpha: useful for local development and experiments, but not yet a stable external tool.
- Strongest areas: Nushell-to-eBPF lowering, MIR/LIR/codegen pipeline, typed contexts, maps/globals, many program-family surfaces, callback subprogram lowering, and shared type-inference/verifier/VCC checks.
- Main risks: kernel-version drift, incomplete live attach coverage for newer or riskier program families, and verifier-parity gaps for complex helper/kfunc state.
- Safety policy: keep host integration tests observational where possible; use dry-run for high-risk families; use isolated VMs for `struct_ops`, scheduler, routing, netfilter, or other behavior-changing live loads.
- Verifier-diff accept metadata is saturated for locally safe fixtures on the current 6.17 development host; remaining accept skips are dry-run-only map-in-map/syscall/freplace cases, VM-only behavior-changing families, unavailable host resources such as LIRC, or source-verified newer-kernel features such as 6.18 path kfuncs.

## Near-Term Priority Order

1. Grow the verifier differential suite and kernel compatibility matrix so correctness is measured against real kernels.
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
  - Add BTF-aware validation for remaining map-value fields that carry verifier-sensitive objects such as nested kernel structs. Dynptr fields are rejected as stack-only verifier objects; source graph root schemas can declare `bpf_list_head:TYPE:FIELD[:record{...}]` / `bpf_rb_root:TYPE:FIELD[:record{...}]`, emit object BTF plus `contains:TYPE:FIELD` declaration tags, validate roots as top-level aligned fields, project graph roots and `bpf_spin_lock` fields from the same map-value record, type acquired object references returned by graph pop/remove/refcount kfuncs from that payload schema, type non-owning front/back/first/left/right graph-node results as the schema object when the node is the compiler-emitted zero-offset field, and require graph-root kfuncs to run under a held `bpf_spin_lock` from the same map lookup root or an independently repeated same-map/same-key lookup root when provenance is available. Bare graph root/node tokens still produce a targeted unsupported-feature diagnostic instead of implying partial support; external graph schemas without internal payload metadata remain future work.
  - Preserve clear diagnostics when VCC rejects a program that the compiler can describe precisely.

- [~] Add a verifier differential suite.
  - Grow `scripts/verifier_diff.nu` from the initial tagged fixture set and optional-`bpftool` kernel load path into the compatibility matrix driver.
  - Use fixture tiers (`fast`, `btf`, `kernel`, `vm-only`) plus default smoke/full selection to keep focused local lanes cheap while preserving heavier BTF/kernel coverage.
  - Track expected accept/reject status, verifier log fragments, required kernel features, and source-verified per-feature minimum kernel versions.
  - Kernel feature records can express minimum and maximum-exclusive kernel windows; keep verifier fixtures aligned with bounded kfunc compatibility when source-checked kfuncs are renamed or removed.
  - Add fixture coverage for maps, helpers, kfuncs, callbacks, context fields, packet bounds, ref lifetimes, dynptrs, timers, and by-reference stack objects.
  - Keep dangerous fixtures dry-run-only or VM-only; the default host lane must remain auto-skip safe. Fixture lists and matrix output now report the derived default test lane separately from fixture tier so safety policy is visible in compatibility dashboards.
  - Keep local compiler/VCC rejects local-only unless the harness gains an explicit negative-kernel corpus that can emit intentionally verifier-rejected objects without bypassing compiler safety by accident; today kernel checks require `local: accept` because they load the dry-run object produced by the compiler.

## Helper, Kfunc, and Callback Semantics

- [~] Keep replacing raw helper usage with honest language forms.
  - Prefer ordinary Nushell syntax and typed context projection over new helper wrappers.
  - Keep `helper-call` and `kfunc-call` as explicit ABI escape hatches for advanced or not-yet-modeled operations.
  - Only add first-class commands when the operation is a real eBPF resource/action without a clear Nushell primitive.
  - Revisit existing first-class commands periodically and remove or narrow any surface that has become redundant.

- [~] Expand typed helper/kfunc semantics where it materially improves safety.
  - Prioritize helpers/kfuncs that affect ownership, lifetime, mutable kernel state, pointer invalidation, by-reference stack objects, or map-value object state.
  - Map-value `bpf_spin_lock` unlock identity, graph-root kfunc same-map-root and repeated same-map/same-key lookup lock checks, copied scalar key aliases, resource spin-lock same-lock duplicate acquire / ordered unlocks, active-lock call restrictions, and typed `bpf_res_spin_lock` pointee validation are now tracked when provenance/type information is available; richer validation that algebraically equivalent key expressions refer to the same concrete entry remains future work.
  - Continue using kernel BTF metadata for unknown kfunc fallback signatures, BTF-described function-pointer callback arguments, exact pointer-return typing, exact pointer-argument pointee validation when BTF exposes a named struct target, pointer-space inference, nullable parameters, constant-size parameters, returned named-pointer projection, and ref-family heuristics.
  - Keep explicit compiler-side metadata for common helpers/kfuncs where kernel BTF is insufficient or too kernel-version-specific.

## Program Model and Context Support

- [~] Keep the program model authoritative.
  - Program type parsing, section naming, context layout, return aliases, helper policy, kfunc policy, capabilities, and live-attach support should continue to flow from shared program metadata.
  - Avoid reintroducing direct `probe_type` or ad hoc target-string matching in compiler, verifier, or loader paths.
  - Add registry invariants when new program families, context fields, aliases, write surfaces, or helper policies are introduced.

- [~] Broaden program-family support without overfitting on `sched_ext`.
  - Use `sched_ext` as a deep vertical for `struct_ops` and kfunc complexity, but keep packet, socket, cgroup, tracing, iterator, LWT, netfilter, flow dissector, and syscall surfaces moving as separate coverage axes.
  - Keep live unclassified or high-risk `struct_ops` families such as `sched_ext_ops`, `hid_bpf_ops`, and `Qdisc_ops` out of normal host tests; use dry-run or VM-only fixtures.
  - Prefer compile/dry-run coverage first for behavior-changing families, then add live attach only when the loader path and test environment are safe.

- [~] Add kernel-version and feature metadata.
  - Keep the program-family and parsed-target compatibility requirement registry authoritative for feature-style requirements. Base program families, BTF tracing/LSM floors, cgroup families, TCX, netfilter links and defrag target flags, LWT, struct_ops family targets such as `tcp_congestion_ops`, `hid_bpf_ops`, `sched_ext_ops`, and `Qdisc_ops`, iterator targets, XDP attach modes and multi-buffer sections, cgroup v2, and cgroup UNIX socket-address hooks now carry source-verified minimums where a kernel version is a meaningful claim.
  - Map-kind kernel floors are now source-backed in `MapKind`, aggregated from compiled object map lists, checked before live load, and derived by verifier fixtures for first-class `--kind` arguments, simple source-visible prior map declarations/operations that seed later no-kind `map-*`, redirect-map, redirect-socket, local-storage helper-surface uses, and ambiguous raw helper map operands, supported raw `helper-call` forms whose map family is fixed by modeled helper metadata, inferred from one source-visible prior map kind by name, or explicit in source as `--kind KIND`, `tail-call`, and reserved helper map arguments such as `events`, `user_events`, `perf_events`, `kstacks`, and `ustacks`; dynamic map pointers and ad hoc helper-only maps whose family is neither fixed nor source-visible should stay explicit until the source scanner can infer them honestly.
  - Typed map-value field floors are source-backed for `bpf_spin_lock`, `bpf_timer`, `kptr:TYPE`, `bpf_wq`, `bpf_refcount`, and graph list/rbtree root/node fields, aggregated from typed map schemas or source-visible `map-define --value-type` tokens, and checked before live load when the typed schema reaches ELF emission.
  - Global data-section compatibility is now tracked from emitted `.data`, `.rodata`, `.bss`, and custom `.data*` / `.rodata*` / `.bss*` data symbols, reported as `global:bpf-data-sections`, and checked before live load against the Linux 5.2 direct-map-value support floor.
  - All modeled helpers now have source-backed `BpfHelper` kernel floors derived from Linux UAPI helper IDs; current verifier `helper-call`, known `kfunc-call`, and target-aware direct/helper-backed `$ctx.FIELD` or `$ctx | get FIELD` fixtures derive their feature metadata from source text; `ebpf spec` exposes direct context-field, backing helper, generated field-read helper, and kfunc feature keys plus version metadata and direct/array/nested load-shape metadata plus direct/array read transforms for read-side context fields, backing ABI fields plus direct/indexed/transformed store-shape metadata for write-side context surfaces, helper-backed projections, mode/kind-sensitive intrinsic variants, intrinsic context-field requirements such as `assign-socket` implying `ctx:sk`, and aggregate intrinsic compatibility floors over always-required backing helpers plus target-specific context-field requirements, including nullable maximum-exclusive windows for kfunc-backed writes and direct writable context-field keys where a write maps to a read-side context ABI; source-checked fixture kfuncs plus most cpumask/dynptr, task/cgroup/socket/map, iterator, object/list/rbtree, user-copy, crypto, sched_ext, preempt/IRQ, and RCU kfuncs have Rust metadata; tracepoint payload field specs expose whether their layout came from tracefs or the syscall fallback, and modeled syscall fallback fields report source-backed layout/syscall-specific floors while tracefs-observed fields remain unversioned; live-load preflight checks helper floors recovered from compiled bytecode, compiler-generated bytecode feature floors, plus known-kfunc and context-field floors preserved from source lowering, includes the effective minimum-kernel source URL in too-old-kernel diagnostics, and includes direct context-write floors that map to read-side fields; and compiled program/object metadata now reports BPF-to-BPF subprogram-call and bounded-loop feature floors in aggregate `compatibility_minimum_kernel` / `compatibility_minimum_kernel_source` plus `compatibility_maximum_kernel_exclusive` when bounded source-verified features are present. Continue tracking remaining kfuncs, source-verified tracepoint field version claims, attach modes, and loader features once each value is source-verified.
  - Kfunc compatibility can express source-checked upper bounds for removed/renamed kfunc windows; legacy sched_ext dispatch/reenqueue spellings that upstream marks for removal in Linux 6.23 now carry maximum-exclusive windows plus source URLs through metadata, `ebpf spec`, compiled program/object aggregates, and too-new-kernel live-load diagnostics, while replacement `___v2` kfunc spellings carry their source-backed introduction floors. Resource spin-lock kfuncs are source-backed from the Linux 6.15 verifier special-kfunc list, and sched_ext per-node idle kfuncs are source-backed from the Linux 6.15 `kernel/sched/ext_idle.c` split.
  - Program-specific kfunc compatibility floors are now modeled where a kfunc expands to new program families after its original introduction. `bpf_dynptr_from_skb` reports the source-verified Linux 6.4 skb-backed packet-family floor and the Linux 6.12 tracing-program floor separately, so compiled objects can aggregate the honest per-program requirement rather than only the kfunc's global floor. Continue adding source-verified per-program floors before broadening future kfunc allowlists.
  - Keep verifier fixture target metadata derived from target strings and source-visible forms where possible; simple direct and helper-backed context fields are derived from target-aware context-parameter field roots, including `$ctx.FIELD`, alternate closure parameter names, direct and indexed context writes such as `$ctx.mark = 7` or `$ctx.cb.1 = 7`, simple full-context aliases such as `let event = ($ctx); $event.FIELD` or transparent identity wrappers such as `let event = (id ($ctx)); $event.FIELD`, simple literal records that carry full context, context-root projections, bound context-root aliases, or those roots through transparent identity wrappers such as `let sk = $ctx.sk; let rec = { k: $ctx socket: (id $sk) }; $rec.socket.family`, record-spread, record pipelines that preserve or reshape context-bearing fields through source-visible `insert` / `update` / `upsert` / `merge` / `select` / `reject` / `rename` / `default`, record-field `get` extraction pipelines that carry direct or `get`-derived roots such as `({ ok: true } | insert socket ($ctx | get sk)) | get socket | get family` or `$rec | get socket | get family`, simple single- and multi-parameter user-function wrappers with direct or `get`-pipeline context arguments, aliases inside multi-parameter wrappers, and transparent identity-wrapped record-wrapper fields, user functions that return context-root aliases such as `def get_sk [c] { $c.sk }; let sk = (get_sk $ctx); $sk.family` or `def get_data [event] { $event | get data }; mut data = (get_data $ctx)`, and nested user-function record-wrapper composition around readable or writable context-root aliases such as `$ctx.data`, `$ctx.data_meta`, `$ctx.optval`, and `$ctx.flow_keys`, simple bound root projections such as `let sk = $ctx.sk; $sk.family`, `let sk = ($ctx.sk); $sk.tcp.snd_cwnd`, and helper-returned socket pointers such as `let tcp = $ctx.sk.tcp; if $tcp { $tcp.snd_cwnd }` or `let full = $ctx.sk.full; if $full { $full.family }`, netfilter trusted-BTF roots like `let state = ($ctx.nf_state); $state.in.ifindex`, iterator BTF roots and aliases such as `$ctx.iter_task.pid` or `let meta = $ctx.iter_meta; $meta.seq_num`, trusted-BTF callback argument projections from modeled helper callbacks, and nested BTF context-arg projections like `$ctx.arg.file.f_flags`, `$ctx.arg0.orig_ax`, cgroup-LSM `$ctx.arg.address.sa_family`, or `let file = $ctx.arg.file; $file.f_flags`; statement-leading source-visible `def` and `for` forms derive compiled-feature floors for BPF-to-BPF calls and bounded loops without treating comments or string literals as language features; typed `map-define --value-type` fields derive map-value floors for `bpf_spin_lock`, `bpf_timer`, `kptr:TYPE`, `bpf_wq`, `bpf_refcount`, and graph roots; first-class packet/message/socket adjustment and redirect surfaces derive their backing helper and source-visible map-kind floors; source-visible aggregate constant bindings derive the global data-section floor; and common source-visible syscall tracepoint payload fields derive tracepoint-specific version claims without being treated as generic context builtins. Helper-only map arguments whose family is neither fixed nor source-visible, complex first-class helper surfaces the scanner cannot imply, unknown kfuncs, unresolved tracepoint fields, or target-specific requirements should remain explicit fixture `kernel_features`.
  - Surface compatibility diagnostics before backend or kernel load when a feature is known to require a newer kernel/config.
  - `ebpf spec` now exposes `live_attach_default_test_lane` alongside compatibility lanes, combining source-verified feature risk with current loader support so dry-run-only targets are machine-readable without losing their underlying feature metadata.
  - Local-kernel detection limits are documented in the README: live-load preflight compares `uname -r` against source-backed feature metadata, while kernel config, distro backports, runtime resources, and unmodeled verifier behavior remain kernel-authoritative. Keep this documentation current as detection expands.

## Maps, Globals, and Resource Modeling

- [~] Finish resource-backed map semantics.
  - Keep generic map operations, local storage, socket maps, redirect maps, cgroup arrays, bloom filters, ring buffers, user ring buffers, stack traces, prog arrays, and per-cpu maps aligned across lowering, type checks, VCC, and backend map emission.
  - Keep local-storage negative coverage in local/VCC lanes unless a future negative-kernel corpus can emit intentionally invalid objects from safe source fixtures without weakening normal compiler rejection.
  - Keep extending source-level `map-define` only for real map resource metadata. Key/value layouts, natural fixed-record alignment, `--max-entries`, and verifier-managed `bpf_timer`, `bpf_spin_lock`, `bpf_wq`, `bpf_refcount`, top-level `kptr:TYPE` slots, and top-level graph root schemas (`bpf_list_head:TYPE:FIELD[:record{...}]` / `bpf_rb_root:TYPE:FIELD[:record{...}]`) are modeled; later operations infer a unique prior kind by map name from `map-define` or earlier explicit `--kind` use before falling back to `hash`; `bpf_wq` init, callback registration, and start are modeled through explicit kfunc calls. Dynptrs remain stack-only helper/kfunc state and are rejected in map-value schemas. Do not expose `bpf_list_head`, `bpf_rb_root`, `bpf_list_node`, or `bpf_rb_node` as bare field tokens; roots must carry named object metadata and graph-root operations must be protected by a held `bpf_spin_lock` from the same map lookup root or a repeated same-map/same-key lookup root when provenance is available, while external schemas without internal graph payload metadata remain future work.
  - Finish map-in-map support. Source-level `map-define --kind array-of-maps|hash-of-maps --inner-map INNER` now validates the inner-template contract against a previously declared inner map, emits declared inner and outer object map definitions even without operations, preserves unambiguous outer-to-inner templates across pinned/shared attach peers, emits libbpf-compatible `values` BTF metadata when the inner template is also emitted as a runtime map, models outer `map-get` results as nullable `bpf_map*` pointers, and supports outer `map-contains` plus guarded dynamic inner `map-get $inner_ptr`, `VALUE | map-put $inner_ptr KEY`, `KEY | map-delete $inner_ptr`, and `KEY | map-contains $inner_ptr` operations in dry-run/object generation. Live loading is intentionally rejected before Aya load because Aya 0.13's map creation path does not materialize `inner_map_fd` from BTF `values` metadata; either an upstream Aya path or a narrow libbpf loader path is needed before this can be live.
  - Add arena support only after map-extra, mmap/user-space access, and verifier constraints are modeled.
  - Keep `struct_ops` maps behind the struct_ops object loader rather than generic `map-*` commands.

- [~] Strengthen global/static data support.
  - Keep broadening fixed-layout globals only when a type annotation or initializer gives an honest byte layout.
  - Keep source-level fixed-record globals, leading typed `mut`, explicit `global-*` declarations, and metadata-built record constants on the same layout/materialization model.
  - Record constants and typed globals can carry nested string, binary, numeric-list, fixed-array, and record fields when their layout is explicit or inferable; fixed-array record elements can carry nested string and numeric-list fields while preserving the materialization metadata needed for ordinary string/list operations.
  - Keep implicit mutable globals consistent with leading typed `mut` and explicit `global-*` declarations.
  - Add clearer diagnostics when a Nushell value cannot be represented as fixed-layout eBPF data.

## Language Surface and Control Flow

- [~] Preserve the small Nushell-first surface.
  - Long-term first-class commands should stay limited to real eBPF operations that do not have honest Nushell equivalents.
  - Keep `map-*` and `global-*` resource-oriented, not a template for adding helper wrappers.
  - Prefer improving ordinary Nushell constant evaluation, records, lists, cell paths, assignments, bounded loops, and function specialization.
  - Keep broadening ordinary stack-backed numeric-list, tracked-string, and metadata-backed fixed-record commands when they can preserve verifier-friendly bounds and honest fixed layouts; current coverage includes common `where` / `each` / `all` / `any` / `first` / `last` / `take` / `skip` / `drop` / `reverse` / `uniq` / small-list `sort` / `compact` / `find` / `get` / `length` / selected non-empty `math` reducers / `is-empty` / `is-not-empty` list paths, byte and compile-time known grapheme-cluster `str length` / literal-prefix `str starts-with` / known-length literal-suffix `str ends-with` / known-length literal-substring `str contains` / compile-time known `str distance` / compile-time known byte and grapheme-cluster `str index-of` / compile-time known `--ignore-case` string predicates / compile-time known byte and grapheme-cluster `str substring` / compile-time known substring and regex `str replace` including `--all`, `--no-expand`, and `--multiline` / compile-time known `str trim` default/`--left`/`--right`/`--char` / compile-time known default `str downcase` / `str upcase` / `str reverse` / `str capitalize` / compile-time known default case conversions such as `str camel-case` / `str kebab-case` / `str pascal-case` / `str screaming-snake-case` / `str snake-case` / `str title-case` / `is-empty` / `is-not-empty` / selected `default` string paths, and `get` / `select` / `reject` / `rename` / `merge` / integer-field `values` / `is-empty` / `is-not-empty` / `insert` / `update` / `upsert` / selected `default` record paths.

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

- [~] Prepare for external alpha consumption.
  - Keep the derived `external_alpha_status` labels in `ebpf spec` aligned with live-attach policy and default test lanes: `live-supported`, `host-gated`, `dry-run-only`, `vm-only`, and `unsafe-opt-in`.
  - Define explicit feature gates for unstable surfaces that need user-facing opt-ins beyond the existing live-attach safety gates.
  - Grow `docs/external-alpha.md` with deeper troubleshooting, packaging expectations, and more status-driven examples.
  - Expand documentation that maps program families to live, compile/dry-run-only, VM-only, unsafe-opt-in, or intentionally unsupported status.
  - Add release notes or a changelog so `TODO.md` does not become a historical progress log again.
  - Decide packaging expectations for the plugin binary, Nushell version compatibility, capabilities setup, and kernel feature detection.

## Definition of Complete Enough

- A user can write non-trivial tracing, packet, cgroup/socket, iterator, and selected struct_ops-style programs in ordinary Nushell syntax with minimal escape hatches.
- The compiler rejects unsupported or unsafe constructs before kernel load whenever the reason is knowable locally.
- Compatibility with representative kernels is measured by automated differential tests, not inferred from one development machine.
- Risky live attach families are gated behind explicit flags and documented VM guidance.
- The README, reference docs, examples, and TODO all describe the same current surface.
