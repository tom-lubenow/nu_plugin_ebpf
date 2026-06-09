const VERIFIER_DIFF_FIXTURES_3035_3038 = [
    {
        name: "assign-socket-rejects-missing-socket"
        category: "language-surface"
        tags: [assign-socket sk-lookup diagnostics reject arguments]
        requires: [netns-self]
        target: "sk_lookup:/proc/self/ns/net"
        program: [
            '{|ctx|'
            '  assign-socket'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "assign-socket requires a socket pointer or null from pipeline input or the first positional argument"
    }
    {
        name: "random-int-rejects-runtime-range"
        category: "language-surface"
        tags: [random diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "random int range must be a compile-time bounded integer range"
    }
    {
        name: "random-int-rejects-reversed-range"
        category: "language-surface"
        tags: [random diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int 5..1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "random int range end must be >= start"
    }
    {
        name: "random-int-rejects-range-too-wide"
        category: "language-surface"
        tags: [random diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  random int 0..4294967296'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "random int eBPF ranges must cover at most 2^32 values"
    }
]
