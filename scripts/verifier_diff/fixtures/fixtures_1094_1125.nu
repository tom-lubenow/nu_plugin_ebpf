const VERIFIER_DIFF_FIXTURES_1094_1125 = [
    {
        name: "iter-cgroup-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:cgroup"
        program: [
            '{|ctx|'
            '  if $ctx.cgroup { $ctx.cgroup.level | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-context"
        category: "context-surface"
        tags: [iter context map]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-map-elem-map-btf-field"
        category: "context-surface"
        tags: [iter context map btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_map_elem"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.value { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-sk-storage-map-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_sk_storage_map"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-context"
        category: "context-surface"
        tags: [iter context map socket]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { 1 | count }'
            '  if $ctx.key { 1 | count }'
            '  if $ctx.sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-sockmap-btf-fields"
        category: "context-surface"
        tags: [iter context map socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:sockmap"
        program: [
            '{|ctx|'
            '  if $ctx.map { $ctx.map.id | count }'
            '  if $ctx.sk { $ctx.sk.__sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-prog-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_prog"
        program: [
            '{|ctx|'
            '  if $ctx.prog { $ctx.prog.len | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-context"
        category: "context-surface"
        tags: [iter context]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-bpf-link-btf-field"
        category: "context-surface"
        tags: [iter context btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:bpf_link"
        program: [
            '{|ctx|'
            '  if $ctx.link { $ctx.link.id | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  $ctx.uid | count'
            '  if $ctx.sk_common { 1 | count }'
            '  if $ctx.sock_common { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-tcp-btf-field"
        category: "context-surface"
        tags: [iter context socket btf kernel-btf]
        requires: [kernel-btf]
        target: "iter:tcp"
        program: [
            '{|ctx|'
            '  if $ctx.sk_common { $ctx.sk_common.skc_family | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "iter-udp-context"
        category: "context-surface"
        tags: [iter context socket]
        target: "iter:udp"
        program: [
            '{|ctx|'
            '  ($ctx.uid + $ctx.bucket) | count'
            '  if $ctx.udp_sk { 1 | count }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
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
