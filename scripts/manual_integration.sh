#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NU_BIN="${NU_BIN:-/home/tom/.nix-profile/bin/nu}"
PLUGIN_BIN="${PLUGIN_BIN:-$REPO_ROOT/target/release/nu_plugin_ebpf}"
SUDO_BIN="${SUDO_BIN:-sudo}"

if [[ ! -x "$NU_BIN" ]]; then
    echo "nu binary not found or not executable: $NU_BIN" >&2
    exit 1
fi

if [[ ! -x "$PLUGIN_BIN" ]]; then
    echo "plugin binary not found or not executable: $PLUGIN_BIN" >&2
    echo "Build it first with: cargo build --release" >&2
    exit 1
fi

run_nu() {
    local script="$1"
    "$SUDO_BIN" "$NU_BIN" -c "plugin add $PLUGIN_BIN; plugin use ebpf; $script"
}

echo "[1/4] stream attach (kprobe:ksys_read)"
run_nu 'ebpf attach -s "kprobe:ksys_read" {|ctx| $ctx.pid | emit } | first 1'

echo "[2/4] attach -> counters -> detach"
run_nu 'let id = (ebpf attach "kprobe:ksys_read" {|ctx| $ctx.pid | count }); sleep 1sec; let rows = ((ebpf counters $id) | length); ebpf detach $id; if $rows < 1 { error make { msg: "expected at least one counter row" } }; { id: $id, rows: $rows }'

echo "[3/4] tracepoint + read-str with null guard"
run_nu 'ebpf attach -s "tracepoint:syscalls/sys_enter_openat" {|ctx| if $ctx.filename != 0 { { pid: $ctx.pid, file: ($ctx.filename | read-str --max-len 32) } | emit } } | first 1'

echo "[4/4] verify no leaked probes"
run_nu 'let remaining = (ebpf list | length); if $remaining != 0 { error make { msg: $"expected empty probe list, got ($remaining)" } }; "ok"'

echo "Manual integration suite passed."
