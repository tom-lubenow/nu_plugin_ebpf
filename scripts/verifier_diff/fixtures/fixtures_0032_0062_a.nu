const VERIFIER_DIFF_FIXTURES_0032_0062_A = [
    {
        name: "tracepoint-fgetxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fgetxattr]
        target: "tracepoint:syscalls/sys_enter_fgetxattr"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.fd + $ctx.size) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-listxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_listxattr]
        target: "tracepoint:syscalls/sys_enter_listxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  $ctx.size | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setxattrat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_setxattrat]
        target: "tracepoint:syscalls/sys_enter_setxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let uargs = $ctx.uargs'
            '  if $uargs { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-listxattrat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_listxattrat]
        target: "tracepoint:syscalls/sys_enter_listxattrat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let list = $ctx.list'
            '  if $list { 1 | count }'
            '  ($ctx.dfd + $ctx.at_flags + $ctx.size) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-close-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_close"
        program: [
            '{|ctx|'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-close-range-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_close_range]
        target: "tracepoint:syscalls/sys_enter_close_range"
        program: [
            '{|ctx|'
            '  ($ctx.fd + $ctx.max_fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat2-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let how = $ctx.how'
            '  if $how { 1 | count }'
            '  ($ctx.dfd + $ctx.usize) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-faccessat2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_faccessat2]
        target: "tracepoint:syscalls/sys_enter_faccessat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-fchmodat2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_fchmodat2]
        target: "tracepoint:syscalls/sys_enter_fchmodat2"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.mode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-readlinkat-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_readlinkat]
        target: "tracepoint:syscalls/sys_enter_readlinkat"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  let buf = $ctx.buf'
            '  if $pathname { $pathname | read-str --max-len 64 | count }'
            '  if $buf { 1 | count }'
            '  ($ctx.dfd + $ctx.bufsiz) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getdents64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getdents64]
        target: "tracepoint:syscalls/sys_enter_getdents64"
        program: [
            '{|ctx|'
            '  let dirent = $ctx.dirent'
            '  if $dirent { 1 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-name-to-handle-at-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_name_to_handle_at]
        target: "tracepoint:syscalls/sys_enter_name_to_handle_at"
        program: [
            '{|ctx|'
            '  let name = $ctx.name'
            '  let handle = $ctx.handle'
            '  let mnt_id = $ctx.mnt_id'
            '  if $name { $name | read-str --max-len 64 | count }'
            '  if $handle { 1 | count }'
            '  if $mnt_id { 1 | count }'
            '  ($ctx.dfd + $ctx.flag) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-legacy-open-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_open]
        target: "tracepoint:syscalls/sys_enter_open"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.flags + $ctx.mode) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-exit-openat2-context"
        category: "tracing"
        tags: [tracepoint context compatibility]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_exit_openat2"
        program: [
            '{|ctx|'
            '  ($ctx.id + $ctx.ret) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-execve-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_execve"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  let argv = $ctx.argv'
            '  if $argv { 1 | count }'
            '  let envp = $ctx.envp'
            '  if $envp { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
