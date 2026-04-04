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

echo "[1/14] stream attach (kprobe:ksys_read)"
run_nu 'ebpf attach -s "kprobe:ksys_read" {|ctx| $ctx.pid | emit } | first 1'

echo "[2/14] attach -> counters -> detach"
run_nu 'let id = (ebpf attach "kprobe:ksys_read" {|ctx| $ctx.pid | count }); sleep 1sec; let rows = ((ebpf counters $id) | length); ebpf detach $id; if $rows < 1 { error make { msg: "expected at least one counter row" } }; { id: $id, rows: $rows }'

echo "[3/14] tracepoint + read-str with null guard"
run_nu 'ebpf attach -s "tracepoint:syscalls/sys_enter_openat" {|ctx| if $ctx.filename != 0 { { pid: $ctx.pid, file: ($ctx.filename | read-str --max-len 32) } | emit } } | first 1'

echo "[4/14] fentry trampoline arg"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:do_sys_openat2' {|ctx| if \$ctx.arg1 != 0 { 1 | count }}); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one fentry trampoline counter row' } }; { id: \$id, rows: \$rows }"

echo "[5/14] fentry pointer-backed trampoline field"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:do_sys_openat2' {|ctx| \$ctx.arg2.flags | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one pointer-backed trampoline field row' } }; { id: \$id, rows: \$rows }"

echo "[6/14] fentry intermediate trampoline pointer hop"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_inode.i_ino | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one intermediate trampoline pointer-hop row' } }; { id: \$id, rows: \$rows }"

echo "[7/14] fentry post-binding pointer field projection"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| let inode = \$ctx.arg0.f_inode; \$inode.i_ino | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one post-binding pointer field row' } }; { id: \$id, rows: \$rows }"

echo "[8/14] fentry deeper post-binding pointer field projection"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| let inode = \$ctx.arg0.f_inode; \$inode.i_sb.s_flags | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one deeper post-binding pointer field row' } }; { id: \$id, rows: \$rows }"

echo "[9/14] fentry trampoline array element"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| \$ctx.arg0.comm.0 | count }); ^true; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one trampoline array-element row' } }; { id: \$id, rows: \$rows }"

echo "[10/14] fentry trampoline array leaf"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| \$ctx.arg0.comm | count }); ^true; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one trampoline array-leaf row' } }; { id: \$id, rows: \$rows }"

echo "[11/14] fentry trampoline struct leaf emit decodes record"
struct_emit_out="$(mktemp)"
trap 'rm -f "$struct_emit_out"' EXIT
run_nu "ebpf attach -s 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_path | emit } | first 1 | columns | sort | to nuon" >"$struct_emit_out" &
struct_emit_pid=$!
sleep 1
cat "$REPO_ROOT/Cargo.toml" >/dev/null
wait "$struct_emit_pid"
if ! grep -qx '\[cpu, dentry, mnt\]' "$struct_emit_out"; then
    echo "expected struct leaf emit to produce record fields cpu/dentry/mnt, got:" >&2
    cat "$struct_emit_out" >&2
    exit 1
fi
rm -f "$struct_emit_out"
trap - EXIT

echo "[12/14] fentry trampoline struct leaf count decodes record key"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_path | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = (ebpf counters \$id); let row_count = (\$rows | length); let key_fields = (\$rows | get 0.key | columns | sort); ebpf detach \$id; if \$row_count < 1 { error make { msg: 'expected at least one struct-leaf counter row' } }; if \$key_fields != [dentry mnt] { error make { msg: \$\"expected record counter key fields [dentry mnt], got (\$key_fields)\" } }; { id: \$id, rows: \$row_count, key_fields: \$key_fields }"

echo "[13/14] fexit trampoline retval"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fexit:do_sys_openat2' {|ctx| \$ctx.retval | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one fexit retval counter row' } }; { id: \$id, rows: \$rows }"

echo "[14/14] verify no leaked probes"
run_nu 'let remaining = (ebpf list | length); if $remaining != 0 { error make { msg: $"expected empty probe list, got ($remaining)" } }; "ok"'

echo "Manual integration suite passed."
