const VERIFIER_DIFF_FIXTURES_2157_2187_B_B = [
    {
        name: "core-context-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-packet-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit packet reject]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  $ctx.data | emit'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-optval-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit cgroup-sockopt reject]
        target: "cgroup_sockopt:/sys/fs/cgroup:get"
        program: [
            '{|ctx|'
            '  $ctx.optval | emit'
            '  "allow"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-flow-keys-pointer-emit-rejects-pointer-escape"
        category: "language-core"
        tags: [context emit flow-dissector reject]
        target: "flow_dissector:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  $ctx.flow_keys | emit'
            '  "fallback"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-histogram-rejects-pointer-escape"
        category: "language-core"
        tags: [context histogram reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | histogram'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-redirect-map-rejects-pointer-escape"
        category: "language-core"
        tags: [context redirect-map reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | redirect-map tx_ports --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-tail-call-rejects-pointer-escape"
        category: "language-core"
        tags: [context tail-call reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx | tail-call jumps'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-read-kernel-str-rejects-pointer-source"
        category: "language-core"
        tags: [context read-kernel-str reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | read-kernel-str'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-packet-rejects-pointer-delta"
        category: "language-core"
        tags: [context adjust-packet reject]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  $ctx | adjust-packet --head'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-bytes"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  $ctx | adjust-message --apply'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
    {
        name: "core-context-adjust-message-rejects-pointer-end"
        category: "language-core"
        tags: [context adjust-message reject]
        target: "sk_msg:/sys/fs/bpf/demo_sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --pull 0 $ctx'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use context pointers as values"
    }
]
