const VERIFIER_DIFF_FIXTURES_2558_2563 = [
    {
        name: "core-string-str-trim-rejects-cell-path-argument"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  " abc " | str trim name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim does not support cell-path arguments in eBPF"
    }
    {
        name: "core-string-str-trim-rejects-dynamic-char"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str trim --char $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim --char requires a compile-time string literal"
    }
    {
        name: "core-string-str-trim-rejects-empty-char"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str trim --char ""'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim --char requires exactly one character in eBPF"
    }
    {
        name: "core-string-str-trim-rejects-multiple-char"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str trim --char "ab"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim --char requires exactly one character in eBPF"
    }
    {
        name: "core-string-str-trim-rejects-dynamic-input"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str trim'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-trim-rejects-list-item-type"
        category: "language-core"
        tags: [string str trim diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [" abc " 1] | str trim'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str trim requires string list items in eBPF; item 1 has type int"
    }
]
