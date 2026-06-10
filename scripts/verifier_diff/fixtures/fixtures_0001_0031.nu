const VERIFIER_DIFF_FIXTURES_0001_0031 = [
    {
        name: "raw-tracepoint-count"
        category: "tracing"
        tags: [raw-tracepoint counter]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.arg1) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-context-param-alias"
        category: "context-surface"
        tags: [raw-tracepoint context source metadata]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|event|'
            '  $event.pid | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-random-context"
        category: "context-surface"
        tags: [raw-tracepoint context random]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.random + $ctx.prandom_u32) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-time-context"
        category: "context-surface"
        tags: [raw-tracepoint context time]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  ($ctx.ktime + $ctx.ktime_boot + $ctx.ktime_tai + $ctx.jiffies) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "raw-tracepoint-coarse-time-reject"
        category: "context-surface"
        tags: [raw-tracepoint context time reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.ktime_coarse | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "ctx.ktime_coarse is not available on raw_tracepoint programs"
    }
    {
        name: "kprobe-multi-context"
        category: "tracing"
        tags: [kprobe-multi context]
        target: "kprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kprobe-multi-task-pt-regs-context"
        category: "context-surface"
        tags: [kprobe-multi context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.arg0 + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-multi-context"
        category: "tracing"
        tags: [kretprobe-multi context]
        target: "kretprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-multi-task-pt-regs-context"
        category: "context-surface"
        tags: [kretprobe-multi context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kretprobe.multi:vfs_*"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.retval + $ctx.retval + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-multi-context"
        category: "tracing"
        tags: [uprobe-multi context]
        target: "uprobe.multi:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-sleepable-context"
        category: "tracing"
        tags: [uprobe sleepable context]
        target: "uprobe.s:/bin/true:main"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-sleepable-context"
        category: "tracing"
        tags: [uretprobe sleepable context]
        target: "uretprobe.s:/bin/true:main"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uprobe-multi-sleepable-context"
        category: "tracing"
        tags: [uprobe-multi sleepable context]
        target: "uprobe.multi.s:/bin/true:*"
        program: [
            '{|ctx|'
            '  let ptr = $ctx.arg0'
            '  if $ptr {'
            '    ($ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-multi-context"
        category: "tracing"
        tags: [uretprobe-multi context]
        target: "uretprobe.multi:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "uretprobe-multi-sleepable-context"
        category: "tracing"
        tags: [uretprobe-multi sleepable context]
        target: "uretprobe.multi.s:/bin/true:*"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid + $ctx.func_ip + $ctx.attach_cookie) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretprobe-context"
        category: "tracing"
        tags: [kretprobe context]
        target: "kretprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ksyscall-context"
        category: "tracing"
        tags: [ksyscall context]
        target: "ksyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.arg0 + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "ksyscall-task-pt-regs-context"
        category: "context-surface"
        tags: [ksyscall context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "ksyscall:nanosleep"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.arg0 + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretsyscall-context"
        category: "tracing"
        tags: [kretsyscall context]
        target: "kretsyscall:nanosleep"
        program: [
            '{|ctx|'
            '  ($ctx.retval + $ctx.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "kretsyscall-task-pt-regs-context"
        category: "context-surface"
        tags: [kretsyscall context task pt-regs helper-backed source metadata]
        requires: [kernel-btf]
        target: "kretsyscall:nanosleep"
        program: [
            '{|ctx|'
            '  let task = $ctx.task'
            '  ($task.pt_regs.retval + $ctx.retval + $ctx.func_ip) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  let filename = $ctx.filename'
            '  if $filename { $filename | read-str --max-len 64 | count }'
            '  ($ctx.dfd + $ctx.flags + $ctx.mode + $ctx.current_task.pid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-openat-common-context"
        category: "tracing"
        tags: [tracepoint context compatibility]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_openat"
        program: [
            '{|ctx|'
            '  ($ctx.id + ($ctx.args | get 0)) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-read-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_read"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { $buf | read-str --max-len 16 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-write-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_write"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { $buf | read-str --max-len 16 | count }'
            '  ($ctx.fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-pread64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_pread64]
        target: "tracepoint:syscalls/sys_enter_pread64"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.fd + $ctx.count + $ctx.pos) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-readv-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_readv]
        target: "tracepoint:syscalls/sys_enter_readv"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-preadv2-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_preadv2]
        target: "tracepoint:syscalls/sys_enter_preadv2"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.pos_l + $ctx.pos_h + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sendfile64-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_sendfile64]
        target: "tracepoint:syscalls/sys_enter_sendfile64"
        program: [
            '{|ctx|'
            '  let offset = $ctx.offset'
            '  if $offset { 1 | count }'
            '  ($ctx.out_fd + $ctx.in_fd + $ctx.count) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-copy-file-range-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_copy_file_range]
        target: "tracepoint:syscalls/sys_enter_copy_file_range"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-splice-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_splice]
        target: "tracepoint:syscalls/sys_enter_splice"
        program: [
            '{|ctx|'
            '  let off_in = $ctx.off_in'
            '  if $off_in { 1 | count }'
            '  let off_out = $ctx.off_out'
            '  if $off_out { 1 | count }'
            '  ($ctx.fd_in + $ctx.fd_out + $ctx.len + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setxattr-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_setxattr]
        target: "tracepoint:syscalls/sys_enter_setxattr"
        program: [
            '{|ctx|'
            '  let pathname = $ctx.pathname'
            '  if $pathname { 1 | count }'
            '  let name = $ctx.name'
            '  if $name { 1 | count }'
            '  let value = $ctx.value'
            '  if $value { 1 | count }'
            '  ($ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
