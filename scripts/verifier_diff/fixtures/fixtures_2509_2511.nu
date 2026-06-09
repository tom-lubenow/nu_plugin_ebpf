const VERIFIER_DIFF_FIXTURES_2509_2511 = [
    {
        name: "core-string-distance-rejects-extra-compare-string"
        category: "language-core"
        tags: [string str distance diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance "nut" "shell"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str distance requires exactly one compare-string argument in eBPF"
    }
    {
        name: "core-string-distance-rejects-dynamic-non-string-input"
        category: "language-core"
        tags: [string str distance diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | str distance "nut"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str distance requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-distance-rejects-dynamic-compare-string"
        category: "language-core"
        tags: [string str distance diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nushell" | str distance $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str distance requires a compile-time string literal"
    }
]
