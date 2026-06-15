const VERIFIER_DIFF_FIXTURES_0032_0062_B = [
    {
        name: "tracepoint-connect-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_connect"
        program: [
            '{|ctx|'
            '  let addr = $ctx.uservaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-sendto-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_sendto"
        program: [
            '{|ctx|'
            '  let buff = $ctx.buff'
            '  if $buff { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.len + $ctx.flags + $ctx.addr_len) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-recvfrom-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_recvfrom"
        program: [
            '{|ctx|'
            '  let ubuf = $ctx.ubuf'
            '  if $ubuf { 1 | count }'
            '  let addr = $ctx.addr'
            '  if $addr { 1 | count }'
            '  let addr_len = $ctx.addr_len'
            '  if $addr_len { 1 | count }'
            '  ($ctx.fd + $ctx.size + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-accept4-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_accept4"
        program: [
            '{|ctx|'
            '  let sockaddr = $ctx.upeer_sockaddr'
            '  if $sockaddr { 1 | count }'
            '  let addrlen = $ctx.upeer_addrlen'
            '  if $addrlen { 1 | count }'
            '  ($ctx.fd + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-socket-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_socket"
        program: [
            '{|ctx|'
            '  ($ctx.family + $ctx.type + $ctx.protocol) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-bind-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-setsockopt-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-recvmmsg-context"
        category: "tracing"
        tags: [tracepoint context]
        requires: [tracefs kernel-btf]
        target: "tracepoint:syscalls/sys_enter_recvmmsg"
        program: [
            '{|ctx|'
            '  let mmsg = $ctx.mmsg'
            '  if $mmsg { 1 | count }'
            '  let timeout = $ctx.timeout'
            '  if $timeout { 1 | count }'
            '  ($ctx.fd + $ctx.vlen + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
