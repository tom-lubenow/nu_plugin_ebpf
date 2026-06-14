[
    {
        target: "tracepoint:syscalls/sys_enter_bind"
        program: [
            '{|ctx|'
            '  let addr = $ctx.umyaddr'
            '  if $addr { 1 | count }'
            '  ($ctx.fd + $ctx.addrlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_bind:field:umyaddr"
            "tracepoint:syscalls/sys_enter_bind:field:fd"
            "tracepoint:syscalls/sys_enter_bind:field:addrlen"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_setsockopt"
        program: [
            '{|ctx|'
            '  let optval = $ctx.optval'
            '  if $optval { 1 | count }'
            '  ($ctx.fd + $ctx.level + $ctx.optname + $ctx.optlen) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_setsockopt:field:optval"
            "tracepoint:syscalls/sys_enter_setsockopt:field:fd"
            "tracepoint:syscalls/sys_enter_setsockopt:field:level"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optname"
            "tracepoint:syscalls/sys_enter_setsockopt:field:optlen"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_recvmmsg:field:mmsg"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:timeout"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:fd"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:vlen"
            "tracepoint:syscalls/sys_enter_recvmmsg:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr"
            "tracepoint:syscalls/sys_enter_getpeername:field:usockaddr_len"
            "tracepoint:syscalls/sys_enter_getpeername:field:fd"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_getrandom"
        program: [
            '{|ctx|'
            '  let buf = $ctx.buf'
            '  if $buf { 1 | count }'
            '  ($ctx.count + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_getrandom:field:buf"
            "tracepoint:syscalls/sys_enter_getrandom:field:count"
            "tracepoint:syscalls/sys_enter_getrandom:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_signalfd4"
        program: [
            '{|ctx|'
            '  let user_mask = $ctx.user_mask'
            '  if $user_mask { 1 | count }'
            '  ($ctx.ufd + $ctx.sizemask + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_signalfd4:field:user_mask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:ufd"
            "tracepoint:syscalls/sys_enter_signalfd4:field:sizemask"
            "tracepoint:syscalls/sys_enter_signalfd4:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:events"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:timeout"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:usig"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:ctx_id"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:min_nr"
            "tracepoint:syscalls/sys_enter_io_pgetevents:field:nr"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_ioprio_set"
        program: [
            '{|ctx|'
            '  ($ctx.which + $ctx.who + $ctx.ioprio) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_ioprio_set:field:which"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:who"
            "tracepoint:syscalls/sys_enter_ioprio_set:field:ioprio"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_add_key:field:_type"
            "tracepoint:syscalls/sys_enter_add_key:field:_description"
            "tracepoint:syscalls/sys_enter_add_key:field:_payload"
            "tracepoint:syscalls/sys_enter_add_key:field:plen"
            "tracepoint:syscalls/sys_enter_add_key:field:ringid"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_mbind"
        program: [
            '{|ctx|'
            '  let nmask = $ctx.nmask'
            '  if $nmask { 1 | count }'
            '  ($ctx.start + $ctx.len + $ctx.mode + $ctx.maxnode + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_mbind:field:nmask"
            "tracepoint:syscalls/sys_enter_mbind:field:start"
            "tracepoint:syscalls/sys_enter_mbind:field:len"
            "tracepoint:syscalls/sys_enter_mbind:field:mode"
            "tracepoint:syscalls/sys_enter_mbind:field:maxnode"
            "tracepoint:syscalls/sys_enter_mbind:field:flags"
        ]
    }
    {
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
        feature_keys: [
            "tracepoint:syscalls/sys_enter_move_pages:field:pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:nodes"
            "tracepoint:syscalls/sys_enter_move_pages:field:status"
            "tracepoint:syscalls/sys_enter_move_pages:field:nr_pages"
            "tracepoint:syscalls/sys_enter_move_pages:field:flags"
        ]
    }
    {
        target: "tracepoint:syscalls/sys_enter_set_mempolicy_home_node"
        program: [
            '{|ctx|'
            '  ($ctx.start + $ctx.len + $ctx.home_node + $ctx.flags) | count'
            '  0'
            '}'
        ]
        feature_keys: [
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:start"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:len"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:home_node"
            "tracepoint:syscalls/sys_enter_set_mempolicy_home_node:field:flags"
        ]
    }
]
