# Development Guide

Contributor-facing workflow notes. See the [README](../README.md) for installation and the [example gallery](examples.md) for runnable snippets.

## Manual Integration Suite

Run the repeatable manual integration checks with the Nu harness in `scripts/manual_integration.nu`. The script auto-selects the newest built plugin from `target/debug/nu_plugin_ebpf` and `target/release/nu_plugin_ebpf` unless `PLUGIN_BIN` is set. Subprocess checks use `nu --no-config-file` so the selected binary is not shadowed by a stale user plugin registry.

The normal host-side harness intentionally avoids live registration for unclassified or high-risk `struct_ops` families. Use `--dry-run` for unknown families, `sched_ext_ops`, `hid_bpf_ops`, and `Qdisc_ops` on development hosts, and only opt into `--unsafe-struct-ops` inside an isolated environment you are willing to reset.

```bash
cargo build
sudo nu ./scripts/manual_integration.nu
```

Override the plugin path if needed:

```bash
PLUGIN_BIN=/path/to/nu_plugin_ebpf sudo nu ./scripts/manual_integration.nu
```

If you want to test with a specific Nu build, run that binary directly:

```bash
sudo target/debug/nu ./scripts/manual_integration.nu
```

## Useful Verification Commands

For local compiler work, start with the fast Rust checks and then run targeted tests around the surface you changed:

```bash
cargo check -q
cargo test -q timer
cargo test -q user_ringbuf
cargo test -q callback_subprogram
```

Use the manual integration suite for host-facing attach/dry-run coverage after compiler changes that affect public Nu syntax, map emission, or loader-visible sections.

## Verifier Differential Harness

Use `scripts/verifier_diff.nu` for small compiler/VCC fixtures that should be compared against the kernel verifier. The harness auto-selects the newest built plugin unless `PLUGIN_BIN` is set, runs local `ebpf attach --dry-run` checks first under `nu --no-config-file` so stale registered plugin signatures cannot shadow the selected binary, and auto-skips kernel verifier loading unless the host has `bpftool`, root privileges, and `/sys/fs/bpf`.

```bash
nu ./scripts/verifier_diff.nu --validate
nu ./scripts/verifier_diff.nu --list
nu ./scripts/verifier_diff.nu --matrix
nu ./scripts/verifier_diff.nu --matrix --compat-kernel 5.10
nu ./scripts/verifier_diff.nu --matrix --json
nu ./scripts/verifier_diff.nu --check-host-syscall-tracepoints
nu ./scripts/verifier_diff.nu --no-kernel
nu ./scripts/verifier_diff.nu --smoke --no-kernel
nu ./scripts/verifier_diff.nu --fast --no-kernel
nu ./scripts/verifier_diff.nu --full --no-kernel
nu ./scripts/verifier_diff.nu --full --no-kernel --jobs 8
nu ./scripts/verifier_diff.nu --fixture raw-tracepoint-count
nu ./scripts/verifier_diff.nu --fixture raw-tracepoint-count --fixture raw-tracepoint-context-param-alias --no-kernel
nu ./scripts/verifier_diff.nu --fixtures [source-helper-sk-lookup-release source-helper-sk-lookup-rejects-leak] --no-kernel
nu ./scripts/verifier_diff.nu --category maps --no-kernel
nu ./scripts/verifier_diff.nu --tier btf --no-kernel
nu ./scripts/verifier_diff.nu --test-lane host-gated --no-kernel
nu ./scripts/verifier_diff.nu --tag reject --local-status reject --no-kernel
sudo nu ./scripts/verifier_diff.nu --kernel
sudo nu ./scripts/verifier_diff.nu --full --kernel
```

Fixtures carry expected local/kernel status, raw targets, category tags, tier metadata, optional local host-feature requirements, optional kernel-only requirements, and per-feature `kernel_features` records for source-verified minimum kernels plus optional maximum-exclusive kernel windows. The harness derives default program-family and attach-mode kernel features from fixture targets, source-level map-kind features from first-class `--kind` arguments and simple prior map-kind declarations/uses that seed later no-kind `map-*`, `redirect-map`, `redirect-socket`, local-storage helper surfaces, and ambiguous raw helper map operands, supported raw `helper-call` forms whose map family is fixed by modeled helper metadata, inferred from one source-visible prior map kind by name, or explicit in source as `--kind KIND`, plus `tail-call` prog-array use, statement-leading `def` / `for` language forms for compiled BPF-to-BPF calls and bounded loops, modeled helper-ID and Rust-backed kfunc features from `helper-call` / `kfunc-call` source text, target-aware direct and helper-backed context-parameter field roots such as `$ctx.FIELD` or `$event.FIELD`, direct context `get` pipelines such as `$ctx | get sk | get family` and `$ctx | get sk.family`, user-function returns of those roots such as `def get_data [event] { $event | get data }; mut data = (get_data $ctx)`, direct and indexed context writes such as `$ctx.mark = 7` or `$ctx.cb.1 = 7`, simple full-context aliases such as `let event = ($ctx); $event.FIELD` and transparent identity wrappers such as `let event = (id ($ctx)); $event.FIELD`, simple literal records that carry the full context, a context-root projection, a bound context-root alias, or those values through transparent identity wrappers such as `let sk = $ctx.sk; let rec = { root: $ctx socket: (id $sk) }; $rec.socket.family`, record pipelines and record-field `get` extraction chains that carry direct or `get`-derived roots such as `({ ok: true } | insert socket ($ctx | get sk)) | get socket | get family` or `$rec | get socket | get family`, read-side context accesses inside simple single- and multi-parameter user functions called as statements or parenthesized expressions such as `read_pid $ctx` or `read_pid 0 $ctx`, context-root aliases inside those functions, record-spread and simple user-function wrappers around writable context-root aliases such as `$ctx.data`, `$ctx.data_meta`, `$ctx.optval`, and `$ctx.flow_keys`, simple bound context-root projections such as `let sk = $ctx.sk; $sk.family`, `let sk = ($ctx.sk); $sk.tcp.snd_cwnd`, helper-returned socket pointers such as `let tcp = $ctx.sk.tcp; if $tcp { $tcp.snd_cwnd }` or `let listener = $ctx.sk.listener; if $listener { $listener.family }`, or `let state = ($ctx.nf_state); $state.in.ifindex`, iterator BTF roots and aliases such as `$ctx.iter_task.pid` or `let meta = $ctx.iter_meta; $meta.seq_num`, trusted-BTF callback argument projections from modeled helper callbacks, nested BTF context-arg projections such as `$ctx.arg.file.f_flags`, `$ctx.arg0.orig_ax`, or `let file = $ctx.arg.file; $file.f_flags`, implicit `bpf_probe_read_kernel` floors for helper-backed kernel socket reads and `tp_btf` pointer-argument scalar projections, trusted-BTF direct scalar loads that do not imply a probe-read helper floor, generic/local-storage/socket-map `map-*` operation helper floors, and simple first-class helper surfaces such as `emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `random int`, `read-str`, `read-kernel-str`, `tail-call`, `redirect-map`, `adjust-packet`, `adjust-message`, `assign-socket`, cgroup-array `map-contains`, and socket redirects. Tracepoint payload names are not treated as generic context builtins, and comments/string literals are not treated as language-feature evidence. Explicit `kernel_features: [{ key, min_kernel, source, max_kernel_exclusive? }]` records should still be used for tracepoint-specific field version claims, helper-only map arguments whose family is neither fixed nor source-visible, first-class helper surfaces the source scanner cannot imply, unknown kfuncs, or target-specific details the target/source scanner cannot imply.

Prefer feature-granular metadata over the legacy fixture-level `min_kernel` / `min_kernel_source` fields because a single fixture can depend on a program type, map kind, helper, kfunc, context field, context write, and attach mode with different introduction kernels. The harness computes `effective_min_kernel`, `effective_max_kernel_exclusive`, and a `default_test_lane` (`host-safe`, `host-gated`, `dry-run`, or `vm-only`) plus `default_test_lane_description` from those records, with an explicit fixture override available when source scanning cannot infer safety honestly. No-filter execution defaults to the smoke lane (`--tier fast --test-lane host-safe`) to keep local and kernel verifier checks cheap; pass `--full` for the complete fixture corpus. `--list` and `--matrix` still report the complete corpus unless a filter such as `--smoke`, `--fast`, `--tier`, or `--test-lane` is selected. Use `--compat-kernel VERSION` with `--list` or `--matrix` to compare fixture requirements against a representative release without booting that kernel; this is meant for compatibility dashboards and release planning, not as a substitute for real verifier runs.

Use `--validate` for a metadata-only guardrail that checks the full fixture corpus without resolving the plugin or printing the full fixture matrix. Use `--check-host-syscall-tracepoints` as a standalone tracefs audit that compares this host's `sys_enter_*` tracepoints with the Rust fallback registry; it is host-kernel-specific and requires tracefs, so keep it out of default runs. Normal selected runs validate only the selected fixtures before execution, so focused `--fixture`, repeated `--fixture`, `--fixtures`, `--category`, `--tag`, `--tier`, `--exclude-tier`, `--test-lane`, `--local-status`, and `--kernel-status` slices stay cheap as the corpus grows. Local dry-runs execute in bounded batches; pass `--jobs N` or set `VERIFIER_DIFF_JOBS` to override the default of 4, and use `--jobs 1` when debugging a single fixture process. `--list --json` and `--matrix --json` emit machine-readable fixture metadata for CI and compatibility dashboards, including raw fixture targets in list summaries. `--matrix` prints coverage counts by tier/category, including versioned versus unversioned kernel-accept fixture counts, bounded versus unbounded compatibility-window counts, and lane totals. With `--compat-kernel`, it also reports how many kernel-accept fixtures are compatible with, require a newer kernel than, or require an older kernel than that release. `--smoke` is shorthand for `--tier fast --test-lane host-safe`, and `--fast` is shorthand for `--tier fast`; fixtures that require kernel BTF or tracefs infer as `btf` unless explicitly annotated, while other fixtures infer as `fast`. Requirements are auto-skipped in broad runs and treated as hard failures when `--kernel` is requested. Keep normal development runs local-only or auto-skip capable. Add kernel-required fixtures only when they are load-only, deterministic, and safe for the host; behavior-changing families should stay dry-run-only here and move to an isolated VM lane.
