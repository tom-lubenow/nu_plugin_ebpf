const VERIFIER_DIFF_FIXTURES_0001_0031_B_B = [
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
