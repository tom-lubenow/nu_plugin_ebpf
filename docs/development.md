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
