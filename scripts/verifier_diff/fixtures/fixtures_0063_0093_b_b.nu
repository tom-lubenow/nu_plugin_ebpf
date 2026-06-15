const VERIFIER_DIFF_FIXTURES_0063_0093_B_B = [
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
