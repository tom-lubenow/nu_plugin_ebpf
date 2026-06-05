# Changelog

This project is still an internal alpha. Until a stable release process exists,
this file records user-facing compiler, loader, diagnostics, compatibility, and
documentation changes that matter to external alpha consumers.

## Unreleased

- Added source verifier coverage for cpumask set-operation and distribution
  kfuncs, including `bpf_cpumask_or`, `bpf_cpumask_xor`, and any-cpu queries.
- Extended source verifier coverage for single-mask cpumask query/mutation
  kfuncs, including test-and-set/clear and first-zero paths.
- Added source verifier coverage for cpumask query/mutation kfunc pointer
  provenance, including scalar-argument rejects.
- Added source verifier coverage for `bpf_throw`, including void-return misuse
  and lock-held kfunc rejects.
- Added source verifier coverage for `bpf_task_under_cgroup` task/cgroup
  pointer provenance, including task-reference misuse rejects.
- Added source verifier coverage for `bpf_map_sum_elem_count` on
  `bpf_for_each_map_elem` callback map pointers and stack-pointer rejects.
- Rejected dynamic `bpf_dynptr_from_mem` flags derived from bounded helper
  return ranges, with source, verifier-types, and VCC coverage.
- Added source verifier coverage for dynamic `bpf_dynptr_read` and
  `bpf_dynptr_write` flags derived from helper return ranges.
- Added source verifier coverage for dynamic `bpf_ringbuf_reserve` and
  `bpf_ringbuf_reserve_dynptr` flags derived from helper return ranges.
- Added source verifier coverage for dynamic `bpf_get_local_storage` and
  `bpf_loop` zero-only flags derived from helper return ranges.
- Added source verifier coverage for constant and dynamic zero-only flags on
  callback helpers `bpf_for_each_map_elem` and `bpf_find_vma`.
- Added source verifier coverage for dynamic flag rejects on branch-stack and
  ringbuf query/drain helpers derived from helper return ranges.
- Added source verifier coverage for dynamic ringbuf wakeup flag rejects on
  submit/discard helpers and their dynptr variants.
- Added source verifier coverage for dynamic XDP/TC network helper flag rejects
  derived from helper return ranges.
- Added source verifier coverage for dynamic map update/push and timer helper
  flag rejects derived from helper return ranges.
- Added source verifier coverage for dynamic sysctl name and strtox helper flag
  rejects derived from helper return ranges.
- Added source verifier coverage for dynamic redirect helper flag rejects
  derived from helper return ranges.
- Added source verifier coverage for dynamic socket redirect helper flag rejects
  derived from helper return ranges.
- Added source verifier coverage for dynamic TC skb mutation helper flag
  rejects derived from helper return ranges.
- Added source verifier coverage for dynamic sock-ops helper flag rejects
  derived from helper return ranges.
- Added source verifier coverage for dynamic stack-copy, stack-id, and
  `bpf_ringbuf_output` flag rejects derived from helper return ranges.
- Added source verifier coverage for dynamic zero-flag rejects on message data
  reshaping, redirect-neigh, skb tail, and xfrm helpers.
- Added source verifier coverage for dynamic `bpf_copy_from_user_task` and
  `bpf_snprintf_btf` flag rejects derived from helper return ranges.
- Added source verifier coverage for dynamic task-storage, BPRM opts, and
  `bpf_sk_assign` flag rejects derived from helper return ranges.
- Added source verifier coverage for dynamic syscall kallsyms flag rejects
  derived from syscall helper return ranges.
- Added source verifier coverage for dynamic perf-event read flag rejects
  derived from helper return ranges and arithmetic range propagation.
- Added source verifier coverage for dynamic `bpf_redirect_neigh` null-params
  length rejects derived from helper return ranges.
- Added source verifier coverage for dynamic null-buffer size rejects on
  copy-from-user, branch-stack, and task-stack helpers.
- Added source verifier coverage for dynamic skb timestamp, load-relative
  start-header, and csum null-side scalar policy rejects.
- Added source verifier coverage for dynamic helper size rejects on
  probe-write-user, stack-copy, d_path, trace-vprintk, and snprintf_btf paths.
- Extended dynamic stack-copy size coverage to task-stack negative-size
  helper paths.
- Added source verifier coverage for dynamic exact-size and iteration-bound
  rejects on namespace, snprintf_btf, perf-event read-value, and bpf_loop paths.
- Added source verifier coverage for dynamic `bpf_path_d_path` zero-size
  rejects from branch-selected helper return ranges.
- Added source verifier coverage for dynamic syscall `bpf_sys_bpf` zero
  attr-size rejects from branch-selected helper return ranges.
- Rejected dynamic scalar ranges that do not prove helper multiple-of
  requirements, with trace-vprintk, seq-printf, and csum source coverage.
- Preserved branch-selected scalar multiple facts so aligned dynamic helper
  sizes, such as tunnel option lengths, can pass without accepting unaligned
  alternatives.
- Preserved simple scalar expression identities across source lowering,
  verifier-types, and VCC so repeated graph-root map lookups using equivalent
  dynamic key expressions satisfy same-map-value `bpf_spin_lock` checks.
- Added source verifier coverage for the modeled `bpf_task_from_vpid` and
  `bpf_task_get_cgroup1` acquired-reference kfunc flows.
- Added dynamic branch coverage for timer and workqueue map-origin rejects,
  including phi-joined concrete-map source metadata.
- Added dynamic branch coverage for workqueue callback map-origin rejects.
- Added source verifier coverage for dynamic helper size ranges against short
  map-backed buffers.
- Extended dynamic helper buffer coverage to `strtox` result buffers and
  tunnel option pointer joins.
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
- Improved map key/value type-spec diagnostics so parser errors name `map key`
  or `map value` instead of `global` when schemas reject before lowering.
- Improved map graph-root type-spec diagnostics so malformed payload schemas keep
  `map value` context in brace-balance errors.
- Improved record type-spec diagnostics so duplicate and reserved fields report
  the offending field path in nested globals and map key/value schemas.
- Improved nested map-value object type-spec diagnostics for dynptr, graph root,
  graph node, and kptr rejects so they report the offending record field.
- Improved nested map-value graph-root schema diagnostics so malformed object
  type, node field, and payload conflicts report the offending record field.
- Added coverage for nested map-value graph-root payload rejects so empty and
  non-record payload schemas keep the offending record field in diagnostics.
- Rejected `array{bpf_refcount:N}` inside map-value graph-root payload schemas
  with diagnostics that name the nested payload field.
- Added coverage for top-level graph-root payload `array{bpf_refcount:N}`
  rejects so they fail during payload parsing before wrapper validation.
- Added compatibility-scanner coverage for rbtree graph-root payload schemas
  that derive both rbtree and `bpf_refcount` map-value feature floors.
- Tightened `bpf_refcount_acquire_impl` type checks so graph object pointers
  must contain a `bpf_refcount` field before acquiring a referenced clone.
- Kept lower verifier/VCC `bpf_refcount_acquire_impl` checks in lockstep with
  type inference for object payloads that lack `bpf_refcount`.
- Added rbtree source verifier coverage for rejecting
  `bpf_refcount_acquire_impl` on projected graph payloads without
  `bpf_refcount`.
- Added list front/back source verifier coverage for rejecting
  `bpf_refcount_acquire_impl` on projected graph payloads without
  `bpf_refcount`.
- Added rbtree remove/left/right source verifier coverage for rejecting
  `bpf_refcount_acquire_impl` on projected graph payloads without
  `bpf_refcount`.
- Added parser and source verifier coverage for graph object payloads whose
  `bpf_refcount` is nested inside a payload record.
- Added list-back source verifier coverage for missing-lock and repeated
  same-map/same-key graph-root lock provenance.
- Added rbtree remove source verifier coverage for missing-lock and repeated
  same-map/same-key graph-root lock provenance.
- Added rbtree add source verifier coverage for missing-lock and repeated
  same-map/same-key graph-root lock provenance.
- Added list push front/back source verifier coverage for missing-lock and
  repeated same-map/same-key graph-root lock provenance.
- Added list pop front/back source verifier coverage for missing-lock and
  repeated same-map/same-key graph-root lock provenance.
- Added rbtree first source verifier coverage for missing-lock graph-root lock
  provenance.
- Added list-back source verifier coverage for rejecting a graph-root protected
  by a spin lock from a different map value.
- Added list push front/back source verifier coverage for rejecting graph roots
  protected by a spin lock from a different map value.
- Added list pop front/back source verifier coverage for rejecting graph roots
  protected by a spin lock from a different map value.
- Added rbtree first/add source verifier coverage for rejecting graph roots
  protected by a spin lock from a different map value.
- Added rbtree remove source verifier coverage for rejecting a graph root
  protected by a spin lock from a different map value.
- Added rbtree right/root source verifier coverage for rejecting list-node
  operands with targeted `bpf_rb_node` diagnostics.
- Added list front/back/pop source verifier coverage for rejecting rbtree-root
  operands with targeted `bpf_list_head` diagnostics.
- Added mutating list and rbtree source verifier coverage for graph-root kind
  mismatches with targeted `bpf_list_head` / `bpf_rb_root` diagnostics.
- Added rbtree remove source verifier coverage for rejecting list-node operands
  with targeted `bpf_rb_node` diagnostics.
- Added bpf_wq source verifier coverage for rejecting non-WQ map fields passed
  to init/start/callback kfuncs.
- Added bpf_wq init source verifier coverage for rejecting nonzero flags.
- Added lower VCC/verifier_types coverage for bpf_wq init/start known-zero
  flag enforcement on nonzero and dynamic operands.
- Added lower VCC/verifier_types coverage for bpf_wq callback flag/aux
  known-zero enforcement on nonzero and dynamic operands.
- Added bpf_wq source verifier coverage for rejecting unknown scalar init,
  start, and callback flags.
- Added lower and source verifier coverage for rejecting nonzero bpf_wq callback
  aux operands.
- Improved known-zero kfunc aux diagnostics so scalar nonzero operands report
  the required zero contract instead of a generic pointer/null mismatch.
- Added type-inference and lower verifier/VCC coverage for packet dynptr
  kfunc flag known-zero diagnostics on nonzero and dynamic operands.
- Added type-inference unit coverage for bpf_wq init/start known-zero flag
  diagnostics on nonzero and dynamic operands.
- Added source verifier coverage for known-zero percpu object-new and list
  push-back aux/meta rejects.
- Added type-inference unit coverage for bpf_wq callback flag/aux known-zero
  diagnostics on nonzero and dynamic operands.
- Added type-inference unit coverage for object and percpu object-new
  known-zero meta diagnostics on nonzero and dynamic operands.
- Added lower verifier/VCC unit coverage for object and percpu object-new
  known-zero meta diagnostics on nonzero and dynamic operands.
- Added type-inference unit coverage for object and percpu object-drop
  known-zero meta diagnostics on nonzero and dynamic operands.
- Added lower verifier/VCC unit coverage for object and percpu object-drop
  known-zero meta diagnostics on nonzero and dynamic operands.
- Added type-inference unit coverage for list push front/back known-zero meta
  diagnostics on nonzero and dynamic operands.
- Added lower verifier/VCC unit coverage for list push front/back known-zero
  meta diagnostics on nonzero and dynamic operands.
- Added type-inference unit coverage for rbtree add known-zero meta diagnostics
  on nonzero and dynamic operands.
- Added lower verifier/VCC unit coverage for rbtree add known-zero meta
  diagnostics on nonzero and dynamic operands.
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
