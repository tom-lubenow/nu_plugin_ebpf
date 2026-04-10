#!/usr/bin/env nu

const TOTAL_STEPS = 65
const COUNTER_TIMEOUT = 5sec
const STREAM_TIMEOUT = 5sec
const POLL_INTERVAL = 100ms
const REPO_ROOT = (path self | path dirname | path dirname)

def fail [msg: string] {
    error make { msg: $msg }
}

def cargo-toml [repo_root: string] {
    $repo_root | path join Cargo.toml
}

def path-is-filelike [path: string] {
    let kind = ($path | path type)
    $kind == 'file' or $kind == 'symlink'
}

def newest-existing [label: string, candidates: list<string>] {
    let existing = (
        $candidates
        | where {|candidate| path-is-filelike $candidate }
        | each {|candidate|
            let meta = (ls -D $candidate | first)
            { path: $candidate, modified: $meta.modified }
        }
        | sort-by modified
        | reverse
    )

    if (($existing | length) == 0) {
        fail $"could not find ($label); checked: ($candidates | str join ', ')"
    }

    $existing | get 0.path
}

def resolve-plugin-bin [repo_root: string] {
    let override = ($env | get -o PLUGIN_BIN)

    if $override != null {
        if (path-is-filelike $override) {
            $override
        } else {
            fail $"plugin binary not found: ($override)"
        }
    } else {
        newest-existing "plugin binary" [
            ($repo_root | path join target debug nu_plugin_ebpf)
            ($repo_root | path join target release nu_plugin_ebpf)
        ]
    }
}

def announce [index: int, label: string] {
    print $"[($index)/($TOTAL_STEPS)] ($label)"
}

def current-nu-bin [] {
    $nu.current-exe
}

def run-nu-with-plugin [plugin_bin: string, code: string] {
    run-external (current-nu-bin) "--plugins" $"[($plugin_bin)]" "-c" $code
}

def step [index: int, label: string, body: closure] {
    announce $index $label
    do $body
}

def safe-detach [id] {
    if $id != null {
        try {
            ebpf detach $id | ignore
        } catch { |_| null }
    }
}

def trigger-cargo-read [repo_root: string] {
    open --raw (cargo-toml $repo_root) | str length | ignore
}

def trigger-sh-true [] {
    ^sh -lc 'true' | ignore
}

def trigger-true [] {
    ^true | ignore
}

def trigger-ping-loopback [] {
    ^ping -c 1 -W 1 127.0.0.1 | ignore
}

def trigger-loopback-connect [] {
    ^bash -lc 'exec 3<>/dev/tcp/127.0.0.1/1 || true' out+err> /dev/null
}

def trigger-loopback-connect6 [] {
    ^python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("::1", 1, 0, 0))
except OSError:
    pass
s.close()
' out+err> /dev/null
}

def trigger-udp-loopback [port: int] {
    ^python3 -c 'import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"nu_plugin_ebpf", ("127.0.0.1", port))
s.close()
' ($port | into string) out+err> /dev/null
}

def trigger-cpu-work [] {
    ^sh -lc 'dd if=/dev/zero of=/dev/null bs=1M count=64 status=none' | ignore
}

def trigger-sysctl-read [] {
    open --raw /proc/sys/kernel/pid_max | str length | ignore
}

def trigger-device-read [] {
    ^cat /dev/null | ignore
}

def trigger-socket-create [] {
    ^python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
' out+err> /dev/null
}

def trigger-sockopt-read [] {
    ^python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
s.close()
' out+err> /dev/null
}

def wait-for-counter-rows [id, label: string] {
    let started = (date now)

    loop {
        let rows = (ebpf counters $id)
        if (($rows | length) > 0) {
            return $rows
        }

        if (((date now) - $started) >= $COUNTER_TIMEOUT) {
            fail $"timed out waiting for counter rows in ($label)"
        }

        sleep $POLL_INTERVAL
    }
}

def assert-row-count [rows, label: string] {
    let row_count = ($rows | length)

    if $row_count < 1 {
        fail $"expected at least one ($label) row"
    }

    $row_count
}

def assert-field-list [actual: list<string>, expected: list<string>, label: string] {
    if $actual != $expected {
        let expected_nuon = ($expected | to nuon)
        let actual_nuon = ($actual | to nuon)
        fail $"expected ($label) fields ($expected_nuon), got ($actual_nuon)"
    }
}

def collect-first-stream [plugin_bin: string, target: string, program: closure, trigger: closure] {
    let job_id = (
        job spawn {
            plugin add $plugin_bin
            plugin use ebpf
            ebpf attach -s $target $program | first 1 | job send 0
        }
    )

    try {
        sleep 100ms
        do $trigger
        let event = (job recv --timeout $STREAM_TIMEOUT | first)
        try {
            job kill $job_id
        } catch { |_| null }
        $event
    } catch { |err|
        try {
            job kill $job_id
        } catch { |_| null }
        error make $err
    }
}

def counter-check [target: string, program: closure, trigger: closure, inspect: closure] {
    let id = (ebpf attach $target $program)

    try {
        do $trigger
        let rows = (wait-for-counter-rows $id $target)
        let result = (do $inspect $id $rows)
        safe-detach $id
        $result
    } catch { |err|
        safe-detach $id
        error make $err
    }
}

def count-at-least-one [target: string, program: closure, trigger: closure, label: string] {
    counter-check $target $program $trigger {|id, rows|
        let row_count = (assert-row-count $rows $label)
        { id: $id, rows: $row_count }
    }
}

def project-entry [entry] {
    $entry
}

def project-inode-flags [file] {
    $file.f_inode.i_flags
}

let repo_root = $REPO_ROOT
let plugin_bin = (resolve-plugin-bin $repo_root)

print $"Using plugin binary: ($plugin_bin)"

plugin add $plugin_bin
plugin use ebpf

step 1 "stream attach (kprobe:ksys_read)" {
    collect-first-stream $plugin_bin "kprobe:ksys_read" {|ctx|
        $ctx.pid | emit
    } { trigger-cargo-read $repo_root }
}

step 2 "attach -> counters -> detach" {
    count-at-least-one "kprobe:ksys_read" {|ctx|
        $ctx.pid | count
    } { trigger-cargo-read $repo_root } "counter"
}

step 3 "tracepoint + read-str with null guard" {
    collect-first-stream $plugin_bin "tracepoint:syscalls/sys_enter_openat" {|ctx|
        if $ctx.filename != 0 {
            { pid: $ctx.pid, file: ($ctx.filename | read-str --max-len 32) } | emit
        }
    } { trigger-cargo-read $repo_root }
}

step 4 "fentry trampoline arg" {
    count-at-least-one "fentry:do_sys_openat2" {|ctx|
        if $ctx.arg1 != 0 {
            1 | count
        }
    } { trigger-cargo-read $repo_root } "fentry trampoline counter"
}

step 5 "fentry pointer-backed trampoline field" {
    count-at-least-one "fentry:do_sys_openat2" {|ctx|
        $ctx.arg2.flags | count
    } { trigger-cargo-read $repo_root } "pointer-backed trampoline field"
}

step 6 "fentry intermediate trampoline pointer hop" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_inode.i_ino | count
    } { trigger-cargo-read $repo_root } "intermediate trampoline pointer hop"
}

step 7 "fentry post-binding pointer field projection" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        let inode = $ctx.arg0.f_inode
        $inode.i_ino | count
    } { trigger-cargo-read $repo_root } "post-binding pointer field"
}

step 8 "fentry deeper post-binding pointer field projection" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        let inode = $ctx.arg0.f_inode
        $inode.i_sb.s_flags | count
    } { trigger-cargo-read $repo_root } "deeper post-binding pointer field"
}

step 9 "fentry multi-level trampoline pointer hop" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        $ctx.arg0.fdt.fd.f_inode.i_ino | count
    } { trigger-sh-true } "multi-level trampoline pointer"
}

step 10 "fentry direct pointer index" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        $ctx.arg0.fdt.fd.0.f_inode.i_ino | count
    } { trigger-sh-true } "direct pointer index"
}

step 11 "fentry bound root trampoline arg" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        let files = $ctx.arg0
        $files.fdt.fd.f_inode.i_ino | count
    } { trigger-sh-true } "bound root trampoline arg"
}

step 12 "fentry bound pointer index" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        let fd = $ctx.arg0.fdt.fd
        $fd.0.f_inode.i_ino | count
    } { trigger-sh-true } "bound pointer index"
}

step 13 "fentry bound numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        let idx = 0
        let fd = ($ctx.arg0.fdt.fd | get $idx)
        $fd.f_inode.i_ino | count
    } { trigger-sh-true } "bound numeric get"
}

step 14 "fentry trampoline array element" {
    count-at-least-one "fentry:wake_up_new_task" {|ctx|
        $ctx.arg0.comm.0 | count
    } { trigger-true } "trampoline array element"
}

step 15 "fentry trampoline array leaf" {
    count-at-least-one "fentry:wake_up_new_task" {|ctx|
        $ctx.arg0.comm | count
    } { trigger-true } "trampoline array leaf"
}

step 16 "fentry trampoline struct leaf emit decodes record" {
    let event = (collect-first-stream $plugin_bin "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | emit
    } { trigger-cargo-read $repo_root })
    let columns = ($event | columns | sort)
    assert-field-list $columns [cpu dentry mnt] "struct leaf emit"
    { fields: $columns }
}

step 17 "fentry trampoline struct leaf count decodes record key" {
    counter-check "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | count
    } { trigger-cargo-read $repo_root } {|id, rows|
        let row_count = (assert-row-count $rows "struct leaf counter")
        let key_fields = ($rows | get 0.key | columns | sort)
        assert-field-list $key_fields [dentry mnt] "struct-leaf counter key"
        { id: $id, rows: $row_count, key_fields: $key_fields }
    }
}

step 18 "fexit trampoline retval" {
    count-at-least-one "fexit:do_sys_openat2" {|ctx|
        $ctx.retval | count
    } { trigger-cargo-read $repo_root } "fexit retval"
}

step 19 "bounded loop-driven numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        for i in 0..0 {
            let fd = ($ctx.arg0.fdt.fd | get $i)
            $fd.f_inode.i_ino | count
        }
    } { trigger-sh-true } "bounded loop numeric get"
}

step 20 "bounded arithmetic-derived numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        for i in 0..1 {
            let j = (($i + 1) mod 2)
            let fd = ($ctx.arg0.fdt.fd | get $j)
            $fd.f_inode.i_ino | count
        }
    } { trigger-sh-true } "bounded arithmetic numeric get"
}

step 21 "typed runtime-field numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        let idx = ($ctx.arg0.fdt.max_fds mod 2)
        let fd = ($ctx.arg0.fdt.fd | get $idx)
        $fd.f_inode.i_ino | count
    } { trigger-sh-true } "typed runtime-field numeric get"
}

step 22 "runtime get on stack-backed array leaf" {
    count-at-least-one "fentry:wake_up_new_task" {|ctx|
        let idx = ($ctx.pid mod 2)
        ($ctx.arg0.comm | get $idx) | count
    } { trigger-true } "stack-backed array numeric get"
}

step 23 "runtime get on stack-backed aggregate bitfield" {
    count-at-least-one "fentry:wake_up_new_task" {|ctx|
        let idx = ($ctx.pid mod 2)
        let clamp = ($ctx.arg0.uclamp_req | get $idx)
        $clamp.value | count
    } { trigger-true } "stack-backed aggregate bitfield"
}

step 24 "runtime get on stack-backed aggregate bitfield struct count decodes record key" {
    counter-check "fentry:wake_up_new_task" {|ctx|
        let idx = ($ctx.pid mod 2)
        let clamp = ($ctx.arg0.uclamp_req | get $idx)
        $clamp | count
    } { trigger-true } {|id, rows|
        let row_count = (assert-row-count $rows "stack-backed aggregate bitfield struct")
        let key_fields = ($rows | get 0.key | columns | sort)
        assert-field-list $key_fields [active bucket_id user_defined value] "bitfield struct key"
        { id: $id, rows: $row_count, key_fields: $key_fields }
    }
}

step 25 "runtime get on stack-backed aggregate bitfield struct emit decodes record" {
    let event = (collect-first-stream $plugin_bin "fentry:wake_up_new_task" {|ctx|
        let idx = ($ctx.pid mod 2)
        let clamp = ($ctx.arg0.uclamp_req | get $idx)
        $clamp | emit
    } { trigger-true })
    let columns = ($event | columns | sort)
    assert-field-list $columns [active bucket_id cpu user_defined value] "bitfield struct emit"
    { fields: $columns }
}

step 26 "branch-refined bound numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        let max = $ctx.arg0.fdt.max_fds
        if $max > 0 {
            let idx = ($max - 1)
            let fd = ($ctx.arg0.fdt.fd | get $idx)
            $fd.f_inode.i_ino | count
        }
    } { trigger-sh-true } "branch-refined numeric get"
}

step 27 "branch-refined direct numeric get" {
    count-at-least-one "fentry:do_close_on_exec" {|ctx|
        if $ctx.arg0.fdt.max_fds > 0 {
            let idx = ($ctx.arg0.fdt.max_fds - 1)
            let fd = ($ctx.arg0.fdt.fd | get $idx)
            $fd.f_inode.i_ino | count
        }
    } { trigger-sh-true } "direct branch-refined numeric get"
}

step 28 "typed generic map put/get projection" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            $entry.dentry.d_flags | count
        }
    } { trigger-cargo-read $repo_root } "typed map put/get"
}

step 29 "typed generic map whole-value count decodes record key" {
    counter-check "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            $entry | count
        }
    } { trigger-cargo-read $repo_root } {|id, rows|
        let row_count = (assert-row-count $rows "whole-value typed map")
        let key_fields = ($rows | get 0.key | columns | sort)
        assert-field-list $key_fields [dentry mnt] "whole-value map key"
        { id: $id, rows: $row_count, key_fields: $key_fields }
    }
}

step 30 "typed generic map whole-value emit decodes record" {
    let event = (collect-first-stream $plugin_bin "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            $entry | emit
        }
    } { trigger-cargo-read $repo_root })
    let columns = ($event | columns | sort)
    assert-field-list $columns [cpu dentry mnt] "whole-value map emit"
    { fields: $columns }
}

step 31 "typed generic map value wrapped into emitted record" {
    let event = (collect-first-stream $plugin_bin "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            { path: $entry } | emit
        }
    } { trigger-cargo-read $repo_root })
    let path_fields = ($event | get path | columns | sort)
    assert-field-list $path_fields [dentry mnt] "nested map record emit"
    { fields: $path_fields }
}

step 32 "typed generic map value through user function emits typed record" {
    let event = (collect-first-stream $plugin_bin "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            (project-entry $entry) | emit
        }
    } { trigger-cargo-read $repo_root })
    let columns = ($event | columns | sort)
    assert-field-list $columns [cpu dentry mnt] "user-function map emit"
    { fields: $columns }
}

step 33 "typed user function projects typed trampoline arg" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        (project-inode-flags $ctx.arg0) | count
    } { trigger-cargo-read $repo_root } "typed user-function trampoline projection"
}

step 34 "typed generic map value copied into second map" {
    count-at-least-one "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
        let entry = ($ctx.pid | map-get cached_path --kind hash)
        if $entry != 0 {
            $entry | map-put copied_path $ctx.pid --kind hash
            let copied = ($ctx.pid | map-get copied_path --kind hash)
            if $copied != 0 {
                $copied.dentry.d_flags | count
            }
        }
    } { trigger-cargo-read $repo_root } "map-to-map copy"
}

step 35 "typed generic map schema persists across pinned programs" {
    let group = "typed_map_schema"
    let writer = (ebpf attach "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put cached_path $ctx.pid --kind hash
    } --pin $group)

    try {
        trigger-cargo-read $repo_root
        let reader = (ebpf attach "fentry:security_file_open" {|ctx|
            let entry = ($ctx.pid | map-get cached_path --kind hash)
            if $entry != 0 {
                $entry.dentry.d_flags | count
            }
        } --pin $group)
        try {
            trigger-cargo-read $repo_root
            let rows = (wait-for-counter-rows $reader "pinned typed map schema")
            let row_count = (assert-row-count $rows "pinned typed map schema")
            safe-detach $reader
            safe-detach $writer
            { writer: $writer, reader: $reader, rows: $row_count }
        } catch { |err|
            safe-detach $reader
            safe-detach $writer
            error make $err
        }
    } catch { |err|
        safe-detach $writer
        error make $err
    }
}

step 36 "xdp loopback ethernet header field counter" {
    count-at-least-one "xdp:lo" {|ctx|
        $ctx.data.eth.ethertype | count
        'pass'
    } { trigger-ping-loopback } "xdp ethernet ethertype counter"
}

step 37 "tc loopback packet length counter" {
    count-at-least-one "tc:lo:ingress" {|ctx|
        $ctx.packet_len | count
        'ok'
    } { trigger-ping-loopback } "tc packet length counter"
}

step 38 "cgroup_skb root egress packet length counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_skb smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_skb:/sys/fs/cgroup:egress" {|ctx|
            $ctx.packet_len | count
            'allow'
        } { trigger-ping-loopback } "cgroup_skb packet length counter"
    }
}

step 39 "xdp loopback ipv4 protocol via variable payload step" {
    count-at-least-one "xdp:lo" {|ctx|
        $ctx.data.eth.payload.ipv4.protocol | count
        'pass'
    } { trigger-ping-loopback } "xdp ipv4 protocol counter"
}

step 40 "captured string constant drives lru generic map name" {
    let map_name = "captured_path"
    count-at-least-one "fentry:security_file_open" {|ctx|
        $ctx.arg0.f_path | map-put $map_name $ctx.pid --kind lru-hash
        let entry = ($ctx.pid | map-get $map_name --kind lru-hash)
        if $entry != 0 {
            $entry.dentry.d_flags | count
        }
    } { trigger-cargo-read $repo_root } "captured string lru map name"
}

step 41 "cgroup_sock_addr root connect4 port counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sock_addr smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_sock_addr:/sys/fs/cgroup:connect4" {|ctx|
            $ctx.user_port | count
            'allow'
        } { trigger-loopback-connect } "cgroup_sock_addr port counter"
    }
}

step 42 "cgroup_sock_addr root connect6 ipv6 word counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sock_addr IPv6 smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else if not ("/proc/net/if_inet6" | path exists) {
        print "Skipping cgroup_sock_addr IPv6 smoke: IPv6 does not appear to be enabled"
    } else {
        count-at-least-one "cgroup_sock_addr:/sys/fs/cgroup:connect6" {|ctx|
            ($ctx.user_ip6 | get 3) | count
            'allow'
        } { trigger-loopback-connect6 } "cgroup_sock_addr ipv6 word counter"
    }
}

step 43 "cgroup_sock root sock_create family counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sock smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_sock:/sys/fs/cgroup:sock_create" {|ctx|
            $ctx.family | count
            'allow'
        } { trigger-socket-create } "cgroup_sock family counter"
    }
}

step 44 "cgroup_device root device major counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_device smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_device:/sys/fs/cgroup" {|ctx|
            $ctx.major | count
            'allow'
        } { trigger-device-read } "cgroup_device major counter"
    }
}

step 45 "sock_ops root cgroup op counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping sock_ops smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "sock_ops:/sys/fs/cgroup" {|ctx|
            $ctx.op | count
            1
        } { trigger-loopback-connect } "sock_ops op counter"
    }
}

step 46 "sock_ops root cgroup args[0] counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping sock_ops args smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "sock_ops:/sys/fs/cgroup" {|ctx|
            ($ctx.args | get 0) | count
            1
        } { trigger-loopback-connect } "sock_ops args[0] counter"
    }
}

step 47 "sock_ops root cgroup snd_cwnd counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping sock_ops snd_cwnd smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "sock_ops:/sys/fs/cgroup" {|ctx|
            $ctx.snd_cwnd | count
            1
        } { trigger-loopback-connect } "sock_ops snd_cwnd counter"
    }
}

step 48 "sock_ops root cgroup skb_len counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping sock_ops skb_len smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "sock_ops:/sys/fs/cgroup" {|ctx|
            $ctx.skb_len | count
            1
        } { trigger-loopback-connect } "sock_ops skb_len counter"
    }
}

step 49 "cgroup_sysctl root read/write counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sysctl smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_sysctl:/sys/fs/cgroup" {|ctx|
            $ctx.write | count
            'allow'
        } { trigger-sysctl-read } "cgroup_sysctl read/write counter"
    }
}

step 50 "cgroup_sockopt root getsockopt counter" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sockopt smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_sockopt:/sys/fs/cgroup:get" {|ctx|
            $ctx.optname | count
            'allow'
        } { trigger-sockopt-read } "cgroup_sockopt getsockopt counter"
    }
}

step 51 "cgroup_sockopt root getsockopt buffer first byte" {
    if not ("/sys/fs/cgroup/cgroup.controllers" | path exists) {
        print "Skipping cgroup_sockopt optval smoke: /sys/fs/cgroup is not a unified cgroup v2 mount"
    } else {
        count-at-least-one "cgroup_sockopt:/sys/fs/cgroup:get" {|ctx|
            ($ctx.optval | get 0) | count
            'allow'
        } { trigger-sockopt-read } "cgroup_sockopt optval first-byte counter"
    }
}

step 52 "sk_lookup root netns local_port counter" {
    count-at-least-one "sk_lookup:/proc/self/ns/net" {|ctx|
        $ctx.local_port | count
        'pass'
    } { trigger-loopback-connect } "sk_lookup local_port counter"
}

step 53 "sk_lookup root netns cookie counter" {
    count-at-least-one "sk_lookup:/proc/self/ns/net" {|ctx|
        $ctx.cookie | count
        'pass'
    } { trigger-loopback-connect } "sk_lookup cookie counter"
}

step 54 "socket_filter udp4 loopback packet length counter" {
    count-at-least-one "socket_filter:udp4:127.0.0.1:41337" {|ctx|
        $ctx.packet_len | count
        'pass'
    } { trigger-udp-loopback 41337 } "socket_filter packet length counter"
}

step 55 "sched_ext_ops dry-run name-only object" {
    let code = ([
        'ebpf attach --dry-run "struct_ops:sched_ext_ops" {'
        '    name: "nu.demo_1"'
        '} | describe'
    ] | str join (char newline))
    let result = (run-nu-with-plugin $plugin_bin $code | str trim)

    if $result != "binary" {
        fail $"expected sched_ext dry-run to return binary, got ($result)"
    }

    $result
}

step 56 "sched_ext_ops dry-run select_cpu cpumask lifecycle" {
    let code = ([
        'ebpf attach --dry-run "struct_ops:sched_ext_ops" {'
        '    name: "nu.demo_1"'
        '    select_cpu: {|ctx|'
        '        let p = $ctx.arg.p'
        '        let prev = $ctx.arg.prev_cpu'
        '        let wake = $ctx.arg.wake_flags'
        '        let mask = (kfunc-call "scx_bpf_get_online_cpumask")'
        '        if $mask != 0 {'
        '            let cpu = (kfunc-call "scx_bpf_select_cpu_and" $p $prev $wake $mask 0)'
        '            kfunc-call "scx_bpf_put_cpumask" $mask'
        '            $cpu'
        '        } else {'
        '            $prev'
        '        }'
        '    }'
        '} | describe'
    ] | str join (char newline))
    let result = (run-nu-with-plugin $plugin_bin $code | str trim)

    if $result != "binary" {
        fail $"expected sched_ext select_cpu dry-run to return binary, got ($result)"
    }

    $result
}

step 57 "tcp_congestion_ops live attach and detach" {
    let code = ([
        'let id = (ebpf attach "struct_ops:tcp_congestion_ops" {'
        '    name: "nu_demo"'
        '    ssthresh: {|ctx| 2 }'
        '    undo_cwnd: {|ctx| 2 }'
        '    cong_avoid: {|ctx| 0 }'
        '})'
        'if $id < 1 {'
        '    error make { msg: $"expected positive struct_ops id, got ($id)" }'
        '}'
        'ebpf detach $id | ignore'
        '$id'
    ] | str join (char newline))
    let id = (run-nu-with-plugin $plugin_bin $code | str trim | into int)

    if $id < 1 {
        fail $"expected positive struct_ops id, got ($id)"
    }

    $id
}

step 58 "lsm file_open dry-run" {
    let code = ([
        'ebpf attach --dry-run "lsm:file_open" {|ctx| $ctx.arg0.f_flags | count; 0 } | describe'
    ] | str join (char newline))
    let result = (run-nu-with-plugin $plugin_bin $code | str trim)

    if $result != "binary" {
        fail $"expected lsm:file_open dry-run to return binary, got ($result)"
    }

    $result
}

step 59 "lsm file_open named-arg dry-run" {
    let code = ([
        'ebpf attach --dry-run "lsm:file_open" {|ctx| $ctx.arg.file.f_flags | count; 0 } | describe'
    ] | str join (char newline))
    let result = (run-nu-with-plugin $plugin_bin $code | str trim)

    if $result != "binary" {
        fail $"expected named-arg lsm:file_open dry-run to return binary, got ($result)"
    }

    $result
}

step 60 "fentry security_file_open named-arg dry-run" {
    let code = ([
        'ebpf attach --dry-run "fentry:security_file_open" {|ctx| $ctx.arg.file.f_flags | count } | describe'
    ] | str join (char newline))
    let result = (run-nu-with-plugin $plugin_bin $code | str trim)

    if $result != "binary" {
        fail $"expected named-arg fentry:security_file_open dry-run to return binary, got ($result)"
    }

    $result
}

step 61 "perf_event software cpu-clock counter" {
    count-at-least-one "perf_event:software:cpu-clock:period=100000" {|ctx|
        $ctx.cpu | count
        0
    } { trigger-cpu-work } "perf_event cpu-clock counter"
}

step 62 "sk_msg pinned sockhash live attach and detach" {
    if not ("/sys/fs/bpf" | path exists) {
        print "Skipping sk_msg smoke: /sys/fs/bpf is not available"
    } else if not ("/usr/sbin/bpftool" | path exists) {
        print "Skipping sk_msg smoke: /usr/sbin/bpftool is not available"
    } else {
        let map_path = $"/sys/fs/bpf/nu_plugin_ebpf_skmsg_($nu.pid)"
        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        let id = (try {
            ^bpftool map create $map_path type sockhash key 4 value 4 entries 16 name nu_skmsg | ignore

            let dry_run_code = ([
                'ebpf attach --dry-run "sk_msg:__MAP__" {|ctx| ($ctx.data | get 0) | count; "pass" } | describe'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            let describe = (run-nu-with-plugin $plugin_bin $dry_run_code | str trim)
            if $describe != "binary" {
                error make { msg: $"expected sk_msg dry-run describe to be 'binary', got ($describe)" }
            }

            let live_code = ([
                'let id = (ebpf attach "sk_msg:__MAP__" {|ctx| $ctx.packet_len | count; "pass" })'
                'if $id < 1 {'
                '    error make { msg: $"expected positive sk_msg id, got ($id)" }'
                '}'
                'ebpf detach $id | ignore'
                '$id'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            run-nu-with-plugin $plugin_bin $live_code | str trim | into int
        } catch { |err|
            try {
                ^rm -f $map_path | ignore
            } catch { |_| null }
            error make $err
        })

        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        if $id < 1 {
            fail $"expected positive sk_msg id, got ($id)"
        }

        $id
    }
}

step 63 "sk_skb pinned sockhash live attach and detach" {
    if not ("/sys/fs/bpf" | path exists) {
        print "Skipping sk_skb smoke: /sys/fs/bpf is not available"
    } else if not ("/usr/sbin/bpftool" | path exists) {
        print "Skipping sk_skb smoke: /usr/sbin/bpftool is not available"
    } else {
        let map_path = $"/sys/fs/bpf/nu_plugin_ebpf_skskb_($nu.pid)"
        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        let id = (try {
            ^bpftool map create $map_path type sockhash key 4 value 4 entries 16 name nu_skskb | ignore

            let dry_run_code = ([
                'ebpf attach --dry-run "sk_skb:__MAP__" {|ctx| ($ctx.ifindex + $ctx.queue_mapping + $ctx.napi_id + $ctx.gso_size + $ctx.vlan_tci + $ctx.eth_protocol + $ctx.vlan_present) | count; "pass" } | describe'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            let describe = (run-nu-with-plugin $plugin_bin $dry_run_code | str trim)
            if $describe != "binary" {
                error make { msg: $"expected sk_skb dry-run describe to be 'binary', got ($describe)" }
            }

            let live_code = ([
                'let id = (ebpf attach "sk_skb:__MAP__" {|ctx| $ctx.packet_len | count; "pass" })'
                'if $id < 1 {'
                '    error make { msg: $"expected positive sk_skb id, got ($id)" }'
                '}'
                'ebpf detach $id | ignore'
                '$id'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            run-nu-with-plugin $plugin_bin $live_code | str trim | into int
        } catch { |err|
            try {
                ^rm -f $map_path | ignore
            } catch { |_| null }
            error make $err
        })

        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        if $id < 1 {
            fail $"expected positive sk_skb id, got ($id)"
        }

        $id
    }
}

step 64 "sk_skb_parser pinned sockhash live attach and detach" {
    if not ("/sys/fs/bpf" | path exists) {
        print "Skipping sk_skb_parser smoke: /sys/fs/bpf is not available"
    } else if not ("/usr/sbin/bpftool" | path exists) {
        print "Skipping sk_skb_parser smoke: /usr/sbin/bpftool is not available"
    } else {
        let map_path = $"/sys/fs/bpf/nu_plugin_ebpf_skskb_parser_($nu.pid)"
        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        let id = (try {
            ^bpftool map create $map_path type sockhash key 4 value 4 entries 16 name nu_skskb_parser | ignore

            let dry_run_code = ([
                'ebpf attach --dry-run "sk_skb_parser:__MAP__" {|ctx| ((($ctx.hash + $ctx.pkt_type + $ctx.tc_classid + $ctx.gso_segs + $ctx.vlan_tci + $ctx.vlan_proto + $ctx.eth_protocol) + ($ctx.hwtstamp mod 17)) + $ctx.vlan_present) | count; 0 } | describe'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            let describe = (run-nu-with-plugin $plugin_bin $dry_run_code | str trim)
            if $describe != "binary" {
                error make { msg: $"expected sk_skb_parser dry-run describe to be 'binary', got ($describe)" }
            }

            let live_code = ([
                'let id = (ebpf attach "sk_skb_parser:__MAP__" {|ctx| $ctx.packet_len | count; 0 })'
                'if $id < 1 {'
                '    error make { msg: $"expected positive sk_skb_parser id, got ($id)" }'
                '}'
                'ebpf detach $id | ignore'
                '$id'
            ] | str join (char newline) | str replace "__MAP__" $map_path)

            run-nu-with-plugin $plugin_bin $live_code | str trim | into int
        } catch { |err|
            try {
                ^rm -f $map_path | ignore
            } catch { |_| null }
            error make $err
        })

        try {
            ^rm -f $map_path | ignore
        } catch { |_| null }

        if $id < 1 {
            fail $"expected positive sk_skb_parser id, got ($id)"
        }

        $id
    }
}

step 65 "verify no leaked probes" {
    let remaining = (ebpf list | length)
    if $remaining != 0 {
        fail $"expected empty probe list, got ($remaining)"
    }
    "ok"
}

print "Manual integration suite passed."
