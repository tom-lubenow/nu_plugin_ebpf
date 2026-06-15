const VERIFIER_DIFF_FIXTURES_0001_0031_B = [
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
]
