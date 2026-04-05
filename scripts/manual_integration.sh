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

echo "[1/29] stream attach (kprobe:ksys_read)"
run_nu 'ebpf attach -s "kprobe:ksys_read" {|ctx| $ctx.pid | emit } | first 1'

echo "[2/29] attach -> counters -> detach"
run_nu 'let id = (ebpf attach "kprobe:ksys_read" {|ctx| $ctx.pid | count }); sleep 1sec; let rows = ((ebpf counters $id) | length); ebpf detach $id; if $rows < 1 { error make { msg: "expected at least one counter row" } }; { id: $id, rows: $rows }'

echo "[3/29] tracepoint + read-str with null guard"
run_nu 'ebpf attach -s "tracepoint:syscalls/sys_enter_openat" {|ctx| if $ctx.filename != 0 { { pid: $ctx.pid, file: ($ctx.filename | read-str --max-len 32) } | emit } } | first 1'

echo "[4/29] fentry trampoline arg"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:do_sys_openat2' {|ctx| if \$ctx.arg1 != 0 { 1 | count }}); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one fentry trampoline counter row' } }; { id: \$id, rows: \$rows }"

echo "[5/29] fentry pointer-backed trampoline field"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:do_sys_openat2' {|ctx| \$ctx.arg2.flags | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one pointer-backed trampoline field row' } }; { id: \$id, rows: \$rows }"

echo "[6/29] fentry intermediate trampoline pointer hop"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_inode.i_ino | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one intermediate trampoline pointer-hop row' } }; { id: \$id, rows: \$rows }"

echo "[7/29] fentry post-binding pointer field projection"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| let inode = \$ctx.arg0.f_inode; \$inode.i_ino | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one post-binding pointer field row' } }; { id: \$id, rows: \$rows }"

echo "[8/29] fentry deeper post-binding pointer field projection"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| let inode = \$ctx.arg0.f_inode; \$inode.i_sb.s_flags | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one deeper post-binding pointer field row' } }; { id: \$id, rows: \$rows }"

echo "[9/29] fentry multi-level trampoline pointer hop"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| \$ctx.arg0.fdt.fd.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one multi-level trampoline pointer row' } }; { id: \$id, rows: \$rows }"

echo "[10/29] fentry direct pointer index"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| \$ctx.arg0.fdt.fd.0.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one direct pointer-index row' } }; { id: \$id, rows: \$rows }"

echo "[11/29] fentry bound root trampoline arg"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| let files = \$ctx.arg0; \$files.fdt.fd.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one bound root trampoline arg row' } }; { id: \$id, rows: \$rows }"

echo "[12/29] fentry bound pointer index"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| let fd = \$ctx.arg0.fdt.fd; \$fd.0.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one bound pointer-index row' } }; { id: \$id, rows: \$rows }"

echo "[13/29] fentry bound numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| let idx = 0; let fd = (\$ctx.arg0.fdt.fd | get \$idx); \$fd.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one bound numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[14/29] fentry trampoline array element"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| \$ctx.arg0.comm.0 | count }); ^true; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one trampoline array-element row' } }; { id: \$id, rows: \$rows }"

echo "[15/29] fentry trampoline array leaf"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| \$ctx.arg0.comm | count }); ^true; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one trampoline array-leaf row' } }; { id: \$id, rows: \$rows }"

echo "[16/29] fentry trampoline struct leaf emit decodes record"
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

echo "[17/29] fentry trampoline struct leaf count decodes record key"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_path | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = (ebpf counters \$id); let row_count = (\$rows | length); let key_fields = (\$rows | get 0.key | columns | sort); ebpf detach \$id; if \$row_count < 1 { error make { msg: 'expected at least one struct-leaf counter row' } }; if \$key_fields != [dentry mnt] { error make { msg: \$\"expected record counter key fields [dentry mnt], got (\$key_fields)\" } }; { id: \$id, rows: \$row_count, key_fields: \$key_fields }"

echo "[18/29] fexit trampoline retval"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fexit:do_sys_openat2' {|ctx| \$ctx.retval | count }); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one fexit retval counter row' } }; { id: \$id, rows: \$rows }"

echo "[19/29] bounded loop-driven numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| for i in 0..0 { let fd = (\$ctx.arg0.fdt.fd | get \$i); \$fd.f_inode.i_ino | count }}); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one bounded loop numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[20/29] bounded arithmetic-derived numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| for i in 0..1 { let j = ((\$i + 1) mod 2); let fd = (\$ctx.arg0.fdt.fd | get \$j); \$fd.f_inode.i_ino | count }}); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one bounded arithmetic numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[21/29] typed runtime-field numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| let idx = (\$ctx.arg0.fdt.max_fds mod 2); let fd = (\$ctx.arg0.fdt.fd | get \$idx); \$fd.f_inode.i_ino | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one typed runtime-field numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[22/29] runtime get on stack-backed array leaf"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| let idx = (\$ctx.pid mod 2); (\$ctx.arg0.comm | get \$idx) | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one stack-backed array numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[23/29] runtime get on stack-backed aggregate bitfield"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| let idx = (\$ctx.pid mod 2); let clamp = (\$ctx.arg0.uclamp_req | get \$idx); \$clamp.value | count }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one stack-backed aggregate bitfield row' } }; { id: \$id, rows: \$rows }"

echo "[24/29] runtime get on stack-backed aggregate bitfield struct count decodes record key"
run_nu "let id = (ebpf attach 'fentry:wake_up_new_task' {|ctx| let idx = (\$ctx.pid mod 2); let clamp = (\$ctx.arg0.uclamp_req | get \$idx); \$clamp | count }); ^sh -lc 'true'; sleep 1sec; let rows = (ebpf counters \$id); let row_count = (\$rows | length); let key_fields = (\$rows | get 0.key | columns | sort); ebpf detach \$id; if \$row_count < 1 { error make { msg: 'expected at least one stack-backed aggregate bitfield struct row' } }; if \$key_fields != [active bucket_id user_defined value] { error make { msg: \$\"expected bitfield struct key fields [active bucket_id user_defined value], got (\$key_fields)\" } }; { id: \$id, rows: \$row_count, key_fields: \$key_fields }"

echo "[25/29] runtime get on stack-backed aggregate bitfield struct emit decodes record"
bitfield_emit_out="$(mktemp)"
trap 'rm -f "$bitfield_emit_out"' EXIT
run_nu "ebpf attach -s 'fentry:wake_up_new_task' {|ctx| let idx = (\$ctx.pid mod 2); let clamp = (\$ctx.arg0.uclamp_req | get \$idx); \$clamp | emit } | first 1 | columns | sort | to nuon" >"$bitfield_emit_out" &
bitfield_emit_pid=$!
sleep 1
"$SUDO_BIN" sh -lc 'true'
wait "$bitfield_emit_pid"
if ! grep -qx '\[active, bucket_id, cpu, user_defined, value\]' "$bitfield_emit_out"; then
    echo "expected bitfield struct emit to produce record fields active/bucket_id/cpu/user_defined/value, got:" >&2
    cat "$bitfield_emit_out" >&2
    exit 1
fi
rm -f "$bitfield_emit_out"
trap - EXIT

echo "[26/29] branch-refined bound numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| let max = \$ctx.arg0.fdt.max_fds; if \$max > 0 { let idx = (\$max - 1); let fd = (\$ctx.arg0.fdt.fd | get \$idx); \$fd.f_inode.i_ino | count } }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one branch-refined numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[27/29] branch-refined direct numeric get"
run_nu "let id = (ebpf attach 'fentry:do_close_on_exec' {|ctx| if \$ctx.arg0.fdt.max_fds > 0 { let idx = (\$ctx.arg0.fdt.max_fds - 1); let fd = (\$ctx.arg0.fdt.fd | get \$idx); \$fd.f_inode.i_ino | count } }); ^sh -lc 'true'; sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one direct branch-refined numeric-get row' } }; { id: \$id, rows: \$rows }"

echo "[28/29] typed generic map put/get projection"
run_nu "let path = '$REPO_ROOT/Cargo.toml'; let id = (ebpf attach 'fentry:security_file_open' {|ctx| \$ctx.arg0.f_path | map-put cached_path \$ctx.pid --kind hash; let entry = (\$ctx.pid | map-get cached_path --kind hash); if \$entry != 0 { \$entry.dentry.d_flags | count }}); let _ = (open --raw \$path | str length); sleep 1sec; let rows = ((ebpf counters \$id) | length); ebpf detach \$id; if \$rows < 1 { error make { msg: 'expected at least one typed map put/get row' } }; { id: \$id, rows: \$rows }"

echo "[29/29] verify no leaked probes"
run_nu 'let remaining = (ebpf list | length); if $remaining != 0 { error make { msg: $"expected empty probe list, got ($remaining)" } }; "ok"'

echo "Manual integration suite passed."
