const VERIFIER_DIFF_FIXTURES_0094_0125_B_B = [
    {
        name: "tracepoint-mmap-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mmap"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.len + $ctx.prot + $ctx.flags + $ctx.fd + $ctx.off) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mprotect-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mprotect"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.prot) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mremap-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mremap"
        program: [
            '{|ctx|'
            '  ($ctx.addr + $ctx.old_len + $ctx.new_len + $ctx.flags + $ctx.new_addr) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mincore-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_mincore"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.start + $ctx.len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-process-madvise-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_process_madvise]
        target: "tracepoint:syscalls/sys_enter_process_madvise"
        program: [
            '{|ctx|'
            '  let vec = $ctx.vec'
            '  if $vec { 1 | count }'
            '  ($ctx.pidfd + $ctx.vlen + $ctx.behavior + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-process-mrelease-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_process_mrelease]
        target: "tracepoint:syscalls/sys_enter_process_mrelease"
        program: [
            '{|ctx|'
            '  ($ctx.pidfd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-memfd-create-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_memfd_create]
        target: "tracepoint:syscalls/sys_enter_memfd_create"
        program: [
            '{|ctx|'
            '  let uname = $ctx.uname'
            '  if $uname { $uname | read-str --max-len 64 | count }'
            '  $ctx.flags | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
