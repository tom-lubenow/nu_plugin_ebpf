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
    {
        name: "tracepoint-getpeername-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getpeername]
        target: "tracepoint:syscalls/sys_enter_getpeername"
        program: [
            '{|ctx|'
            '  let usockaddr = $ctx.usockaddr'
            '  let usockaddr_len = $ctx.usockaddr_len'
            '  if $usockaddr { 1 | count }'
            '  if $usockaddr_len { 1 | count }'
            '  $ctx.fd | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-getrandom-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_getrandom]
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-signalfd4-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_signalfd4]
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-io-pgetevents-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_io_pgetevents]
        target: "tracepoint:syscalls/sys_enter_io_pgetevents"
        program: [
            '{|ctx|'
            '  let events = $ctx.events'
            '  let timeout = $ctx.timeout'
            '  let usig = $ctx.usig'
            '  if $events { 1 | count }'
            '  if $timeout { 1 | count }'
            '  if $usig { 1 | count }'
            '  ($ctx.ctx_id + $ctx.min_nr + $ctx.nr) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-ioprio-set-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_ioprio_set]
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-add-key-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_add_key]
        target: "tracepoint:syscalls/sys_enter_add_key"
        program: [
            '{|ctx|'
            '  let key_type = $ctx._type'
            '  let description = $ctx._description'
            '  let payload = $ctx._payload'
            '  if $key_type { 1 | count }'
            '  if $description { 1 | count }'
            '  if $payload { 1 | count }'
            '  ($ctx.plen + $ctx.ringid) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-mbind-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_mbind]
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "tracepoint-move-pages-context"
        category: "tracing"
        tags: [tracepoint context source metadata]
        requires: [tracefs kernel-btf tracepoint:syscalls/sys_enter_move_pages]
        target: "tracepoint:syscalls/sys_enter_move_pages"
        program: [
            '{|ctx|'
            '  let pages = $ctx.pages'
            '  let nodes = $ctx.nodes'
            '  let status = $ctx.status'
            '  if $pages { 1 | count }'
            '  if $nodes { 1 | count }'
            '  if $status { 1 | count }'
            '  ($ctx.nr_pages + $ctx.flags) | count'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
