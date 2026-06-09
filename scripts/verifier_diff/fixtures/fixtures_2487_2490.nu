const VERIFIER_DIFF_FIXTURES_2487_2490 = [
    {
        name: "core-string-str-length-rejects-extra-argument"
        category: "language-core"
        tags: [string str length diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length does not accept arguments in eBPF"
    }
    {
        name: "core-string-str-length-rejects-duplicate-mode-flags"
        category: "language-core"
        tags: [string str length diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str length --chars --utf-8-bytes'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length accepts only one length mode flag in eBPF"
    }
    {
        name: "core-string-str-length-rejects-dynamic-non-string-input"
        category: "language-core"
        tags: [string str length diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires a tracked string input in eBPF"
    }
    {
        name: "core-string-str-length-rejects-list-item-type"
        category: "language-core"
        tags: [string str length diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["a" 1] | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str length requires string list items in eBPF; item 1 has type int"
    }
]
