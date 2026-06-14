const VERIFIER_DIFF_FIXTURES_0001_0031_A = [
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
]
