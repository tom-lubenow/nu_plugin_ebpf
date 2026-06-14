const VERIFIER_DIFF_FIXTURES_1094_1125_B = [
    {
        name: "iter-udp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  if $ctx.udp_sk { $ctx.udp_sk.inet.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.unix_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-unix-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:unix"
        program: [
            '{|ctx|'
            '  if $ctx.unix_sk { $ctx.unix_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-dmabuf-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:dmabuf"
        program: [
            '{|ctx|'
            '  if $ctx.dmabuf { $ctx.dmabuf.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { 1 | count }'
            '  if $ctx.ipv6_route { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ipv6-route-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ipv6_route"
        program: [
            '{|ctx|'
            '  if $ctx.rt { $ctx.rt.fib6_metric | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-kmem-cache-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:kmem_cache"
        program: [
            '{|ctx|'
            '  if $ctx.kmem_cache { $ctx.kmem_cache.size | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-ksym-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:ksym"
        program: [
            '{|ctx|'
            '  if $ctx.ksym { $ctx.ksym.value | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-netlink-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:netlink"
        program: [
            '{|ctx|'
            '  if $ctx.netlink_sk { $ctx.netlink_sk.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-rejects-queue"
        category: "maps"
        tags: [queue reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-get q --kind queue'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for map kind queue"
    }
    {
        name: "map-define-kptr-slot"
        category: "maps"
        tags: [maps map-define kptr accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind array --value-type "record{task:kptr:task_struct,cookie:u64}" --max-entries 1'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-define-kptr-slot-rejects-queue"
        category: "maps"
        tags: [maps map-define kptr reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define task_slots --kind queue --value-type "record{task:kptr:task_struct,cookie:u64}"'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "kptr fields, which are currently supported for hash, array, and lru-hash maps"
    }
]
