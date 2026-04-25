# Development Guide

Contributor-facing workflow notes. See the [README](../README.md) for installation and the [example gallery](examples.md) for runnable snippets.

## Manual Integration Suite

Run the repeatable manual integration checks with the Nu harness in `scripts/manual_integration.nu`. The script auto-selects the newest built plugin from `target/debug/nu_plugin_ebpf` and `target/release/nu_plugin_ebpf` unless `PLUGIN_BIN` is set.

The normal host-side harness intentionally avoids live `sched_ext` registration. Use `--dry-run` for `sched_ext_ops` on development hosts, and only opt into `--unsafe-struct-ops` inside an isolated environment you are willing to reset.

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

Use `scripts/verifier_diff.nu` for small compiler/VCC fixtures that should be compared against the kernel verifier. The harness auto-selects the newest built plugin unless `PLUGIN_BIN` is set, runs local `ebpf attach --dry-run` checks first, and auto-skips kernel verifier loading unless the host has `bpftool`, root privileges, and `/sys/fs/bpf`.

```bash
nu ./scripts/verifier_diff.nu --list
nu ./scripts/verifier_diff.nu --no-kernel
nu ./scripts/verifier_diff.nu --fixture raw-tracepoint-count
nu ./scripts/verifier_diff.nu --category maps --no-kernel
nu ./scripts/verifier_diff.nu --tag reject --local-status reject --no-kernel
sudo nu ./scripts/verifier_diff.nu --kernel
```

Fixtures carry expected local/kernel status, category tags, and optional host-feature requirements. Use `--fixture`, `--category`, `--tag`, `--local-status`, and `--kernel-status` to run focused slices as the fixture set grows. Host-feature requirements are auto-skipped in broad runs and treated as hard failures when `--kernel` is requested. Keep normal development runs local-only or auto-skip capable. Add kernel-required fixtures only when they are load-only, deterministic, and safe for the host; behavior-changing families should stay dry-run-only here and move to an isolated VM lane.
