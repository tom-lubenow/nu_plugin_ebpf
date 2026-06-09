const VERIFIER_DIFF_FIXTURES_2512_2513 = [
    {
        name: "core-string-join-rejects-dynamic-separator"
        category: "language-core"
        tags: [string str join diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" "b"] | str join $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str join separator requires a compile-time string literal"
    }
    {
        name: "core-string-join-rejects-runtime-string-input"
        category: "language-core"
        tags: [string str join diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str join ":"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str join requires compile-time known string input in eBPF"
    }
]
