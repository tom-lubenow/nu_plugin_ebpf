# Development Guide

Contributor-facing workflow notes. See the [README](../README.md) for installation and the [example gallery](examples.md) for runnable snippets.

## Manual Integration Suite

Run the repeatable manual integration checks with the Nu harness in `scripts/manual_integration.nu`. The script auto-selects the newest built plugin from `target/debug/nu_plugin_ebpf` and `target/release/nu_plugin_ebpf` unless `PLUGIN_BIN` is set. Subprocess checks use `nu --no-config-file` so the selected binary is not shadowed by a stale user plugin registry.

The normal host-side harness intentionally avoids live registration for high-risk `struct_ops` families. Use `--dry-run` for `sched_ext_ops`, `hid_bpf_ops`, and `Qdisc_ops` on development hosts, and only opt into `--unsafe-struct-ops` inside an isolated environment you are willing to reset.

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
nu ./scripts/verifier_diff.nu --list
nu ./scripts/verifier_diff.nu --matrix
nu ./scripts/verifier_diff.nu --matrix --compat-kernel 5.10
nu ./scripts/verifier_diff.nu --matrix --json
nu ./scripts/verifier_diff.nu --fast --no-kernel
nu ./scripts/verifier_diff.nu --no-kernel
nu ./scripts/verifier_diff.nu --fixture raw-tracepoint-count
nu ./scripts/verifier_diff.nu --category maps --no-kernel
nu ./scripts/verifier_diff.nu --tier btf --no-kernel
nu ./scripts/verifier_diff.nu --tag reject --local-status reject --no-kernel
sudo nu ./scripts/verifier_diff.nu --kernel
```

Fixtures carry expected local/kernel status, category tags, tier metadata, optional local host-feature requirements, optional kernel-only requirements, and per-feature `kernel_features` records for source-verified minimum kernels plus optional maximum-exclusive kernel windows. The harness derives default program-family and attach-mode kernel features from fixture targets, source-level map-kind features from first-class `--kind` arguments plus `tail-call` prog-array use, modeled helper-ID and Rust-backed kfunc features from `helper-call` / `kfunc-call` source text, target-aware direct and helper-backed `$ctx.FIELD` roots, generic/local-storage/socket-map `map-*` operation helper floors, and simple first-class helper surfaces such as `emit`, `count`, `histogram`, `start-timer`, `stop-timer`, `random int`, `read-str`, `read-kernel-str`, `tail-call`, `redirect-map`, `adjust-packet`, `adjust-message`, `assign-socket`, cgroup-array `map-contains`, and socket redirects. Explicit `kernel_features: [{ key, min_kernel, source, max_kernel_exclusive? }]` records should still be used for tracepoint-specific fields, helper-only map arguments, first-class helper surfaces the source scanner cannot imply, unknown kfuncs, or target-specific details the target/source scanner cannot imply. Prefer feature-granular metadata over the legacy fixture-level `min_kernel` / `min_kernel_source` fields because a single fixture can depend on a program type, map kind, helper, kfunc, context field, and attach mode with different introduction kernels. The harness computes `effective_min_kernel` and `effective_max_kernel_exclusive` from those records and skips kernel checks when the host kernel is too old or too new for a bounded feature. Use `--compat-kernel VERSION` with `--list` or `--matrix` to compare fixture requirements against a representative release without booting that kernel; this is meant for compatibility dashboards and release planning, not as a substitute for real verifier runs. Use `--fixture`, `--category`, `--tag`, `--tier`, `--exclude-tier`, `--local-status`, and `--kernel-status` to run focused slices as the fixture set grows. `--list --json` and `--matrix --json` emit machine-readable fixture metadata for CI and compatibility dashboards. `--matrix` prints coverage counts by tier/category, including versioned versus unversioned kernel-accept fixture counts. With `--compat-kernel`, it also reports how many kernel-accept fixtures are compatible with or require a newer kernel than that release. `--fast` is shorthand for `--tier fast`; fixtures that require kernel BTF or tracefs infer as `btf` unless explicitly annotated, while other fixtures infer as `fast`. Requirements are auto-skipped in broad runs and treated as hard failures when `--kernel` is requested. Keep normal development runs local-only or auto-skip capable. Add kernel-required fixtures only when they are load-only, deterministic, and safe for the host; behavior-changing families should stay dry-run-only here and move to an isolated VM lane.
