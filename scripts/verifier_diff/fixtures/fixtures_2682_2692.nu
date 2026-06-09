const VERIFIER_DIFF_FIXTURES_2682_2692 = [
    {
        name: "core-intrinsic-adjust-packet-rejects-missing-mode"
        category: "program-intrinsics"
        tags: [intrinsics adjust-packet diagnostics reject mode xdp]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet requires exactly one of --head, --meta, --tail, --pull, or --room"
    }
    {
        name: "core-intrinsic-adjust-packet-rejects-multiple-modes"
        category: "program-intrinsics"
        tags: [intrinsics adjust-packet diagnostics reject mode xdp]
        target: "xdp:lo"
        program: [
            '{|ctx|'
            '  adjust-packet --head --tail 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet requires exactly one of --head, --meta, --tail, --pull, or --room"
    }
    {
        name: "core-intrinsic-adjust-message-rejects-missing-mode"
        category: "program-intrinsics"
        tags: [intrinsics adjust-message diagnostics reject mode sk-msg]
        target: "sk_msg:/sys/fs/bpf/sockmap"
        program: [
            '{|ctx|'
            '  adjust-message'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message requires exactly one of --apply, --cork, --pull, --push, or --pop"
    }
    {
        name: "core-intrinsic-adjust-message-rejects-multiple-modes"
        category: "program-intrinsics"
        tags: [intrinsics adjust-message diagnostics reject mode sk-msg]
        target: "sk_msg:/sys/fs/bpf/sockmap"
        program: [
            '{|ctx|'
            '  adjust-message --apply --cork 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message requires exactly one of --apply, --cork, --pull, --push, or --pop"
    }
    {
        name: "core-intrinsic-redirect-rejects-peer-neigh"
        category: "program-intrinsics"
        tags: [intrinsics redirect diagnostics reject flags tc]
        target: "tc:lo:ingress"
        program: [
            '{|ctx|'
            '  redirect --peer --neigh 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect accepts at most one of --peer or --neigh"
    }
    {
        name: "core-intrinsic-adjust-packet-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics adjust-packet diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  adjust-packet --head 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-packet is not supported on kprobe programs"
    }
    {
        name: "core-intrinsic-adjust-message-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics adjust-message diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  adjust-message --apply 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "adjust-message is not supported on kprobe programs"
    }
    {
        name: "core-intrinsic-redirect-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics redirect diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  redirect 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect is not supported on kprobe programs"
    }
    {
        name: "core-intrinsic-redirect-map-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics redirect-map diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  redirect-map tx_ports 0 --kind devmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-map is not supported on kprobe programs"
    }
    {
        name: "core-intrinsic-redirect-socket-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics redirect-socket diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  redirect-socket sockets 0 --kind sockmap'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "redirect-socket is not supported on kprobe programs"
    }
    {
        name: "core-intrinsic-assign-socket-rejects-kprobe-context"
        category: "program-intrinsics"
        tags: [intrinsics assign-socket diagnostics reject context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  assign-socket 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "assign-socket is not supported on kprobe programs"
    }
]
