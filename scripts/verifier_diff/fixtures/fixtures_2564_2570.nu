const VERIFIER_DIFF_FIXTURES_2564_2570 = [
    {
        name: "core-string-fill-rejects-dynamic-width"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | fill --width $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill --width requires a compile-time known integer in eBPF"
    }
    {
        name: "core-string-fill-rejects-negative-width"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | fill --width -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill --width requires a non-negative integer in eBPF"
    }
    {
        name: "core-string-fill-rejects-dynamic-alignment"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | fill --alignment $ctx.comm --width 5'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill --alignment requires a compile-time string literal"
    }
    {
        name: "core-string-fill-rejects-dynamic-character"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | fill --character $ctx.comm --width 5'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill --character requires a compile-time string literal"
    }
    {
        name: "core-string-fill-rejects-nul-character"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | fill --character "\u{0000}" --width 5'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill --character does not support NUL bytes in eBPF"
    }
    {
        name: "core-string-fill-rejects-dynamic-input"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | fill --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill requires compile-time known string, int, float, or filesize input in eBPF"
    }
    {
        name: "core-string-fill-rejects-list-item-type"
        category: "language-core"
        tags: [string fill diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" true] | fill --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "fill supports only string, int, float, and filesize compile-time list items in eBPF; item 1 has type bool"
    }
]
