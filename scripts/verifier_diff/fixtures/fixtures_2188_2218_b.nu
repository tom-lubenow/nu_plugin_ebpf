const VERIFIER_DIFF_FIXTURES_2188_2218_B = [
    {
        name: "core-context-map-delete-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-delete seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-map-contains-rejects-pointer-key"
        category: "language-core"
        tags: [context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | map-contains seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-get-rejects-pointer-key"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-get seen --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-cgroup-array-contains-rejects-pointer-index"
        category: "language-core"
        tags: [record context map cgroup-array reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-contains cgroups --kind cgroup-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-map-put-rejects-pointer-escape"
        category: "language-core"
        tags: [record context map reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | map-put seen 0 --kind hash'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-count-rejects-pointer-escape"
        category: "language-core"
        tags: [record context count reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | count'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [record context packet emit reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  { data: $ctx.data } | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-set-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-set state'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-record-context-global-define-zero-rejects-pointer-escape"
        category: "language-core"
        tags: [record context global reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  { k: $ctx } | global-define state --zero'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "adjust-packet-xdp-head"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-head-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --head 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-head-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta"
        category: "language-surface"
        tags: [adjust-packet xdp]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "adjust-packet-xdp-meta-rejects-stale-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds reject]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  let data = $ctx.data'
            '  adjust-packet --meta 0'
            '  ($data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "stale packet pointer"
    }
    {
        name: "adjust-packet-xdp-meta-allows-reloaded-data"
        category: "language-surface"
        tags: [adjust-packet xdp packet-bounds accept]
        requires: [loopback-interface]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --meta 0'
            '  ($ctx.data | get 0) | count'
            '  "pass"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
