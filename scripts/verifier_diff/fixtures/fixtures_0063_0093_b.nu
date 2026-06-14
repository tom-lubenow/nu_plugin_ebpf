const VERIFIER_DIFF_FIXTURES_0063_0093_B = [
    {
        name: "tracepoint-clone-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_clone]
        target: "tracepoint:syscalls/sys_enter_clone"
        program: [
            '{|ctx|'
            '  let parent_tidptr = $ctx.parent_tidptr'
            '  let child_tidptr = $ctx.child_tidptr'
            '  if $parent_tidptr { 1 | count }'
            '  if $child_tidptr { 1 | count }'
            '  ($ctx.clone_flags + $ctx.newsp + $ctx.tls) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-syslog-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_syslog]
        target: "tracepoint:syscalls/sys_enter_syslog"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.type + $ctx.len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-personality-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_personality]
        target: "tracepoint:syscalls/sys_enter_personality"
        program: [
            '{|ctx|'
            '  $ctx.personality | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-newfstatat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_newfstatat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let statbuf = $ctx.statbuf'
            '  if $statbuf { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-statx-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_statx"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let buffer = $ctx.buffer'
            '  if $buffer { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mask) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mknod-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mknod]
        target: "tracepoint:syscalls/sys_enter_mknod"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.mode + $ctx.dev) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-renameat2-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_renameat2"
        program: [
            '{|ctx|'
            '  let oldname = $ctx.oldname'
            '  if $oldname { $oldname | read-str --max-len 64 | count }'
            '  let newname = $ctx.newname'
            '  if $newname { $newname | read-str --max-len 64 | count }'
            '  ($ctx.olddfd + $ctx.newdfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-linkat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_linkat"
        program: [
            '{|ctx|'
            '  let oldname = $ctx.oldname'
            '  if $oldname { $oldname | read-str --max-len 64 | count }'
            '  let newname = $ctx.newname'
            '  if $newname { $newname | read-str --max-len 64 | count }'
            '  ($ctx.olddfd + $ctx.newdfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-open-tree-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_open_tree]
        target: "tracepoint:syscalls/sys_enter_open_tree"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-move-mount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_move_mount]
        target: "tracepoint:syscalls/sys_enter_move_mount"
        program: [
            '{|ctx|'
            '  let from_pathname = $ctx.from_pathname'
            '  let to_pathname = $ctx.to_pathname'
            '  if $from_pathname { $from_pathname | read-str --max-len 64 | count }'
            '  if $to_pathname { $to_pathname | read-str --max-len 64 | count }'
            '  ($ctx.from_dfd + $ctx.to_dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsopen-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsopen]
        target: "tracepoint:syscalls/sys_enter_fsopen"
        program: [
            '{|ctx|'
            '  let fs_name = $ctx._fs_name'
            '  if $fs_name { $fs_name | read-str --max-len 64 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsconfig-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsconfig]
        target: "tracepoint:syscalls/sys_enter_fsconfig"
        program: [
            '{|ctx|'
            '  let key = $ctx._key'
            '  let value = $ctx._value'
            '  if $key { $key | read-str --max-len 64 | count }'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.cmd + $ctx.aux) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fsmount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fsmount]
        target: "tracepoint:syscalls/sys_enter_fsmount"
        program: [
            '{|ctx|'
            '  ($ctx.fs_fd + $ctx.flags + $ctx.attr_flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fspick-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fspick]
        target: "tracepoint:syscalls/sys_enter_fspick"
        program: [
            '{|ctx|'
            '  let path = $ctx.path'
            '  if $path { $path | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mount-setattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mount_setattr]
        target: "tracepoint:syscalls/sys_enter_mount_setattr"
        program: [
            '{|ctx|'
            '  let path = $ctx.path'
            '  let uattr = $ctx.uattr'
            '  if $path { $path | read-str --max-len 64 | count }'
            '  if $uattr { 1 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-statmount-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_statmount]
        target: "tracepoint:syscalls/sys_enter_statmount"
        program: [
            '{|ctx|'
            '  let req = $ctx.req'
            '  let buf = $ctx.buf'
            '  if $req { 1 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.bufsize + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
