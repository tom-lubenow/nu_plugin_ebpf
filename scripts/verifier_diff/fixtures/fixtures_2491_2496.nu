const VERIFIER_DIFF_FIXTURES_2491_2496 = [
    {
        name: "core-string-starts-with-rejects-extra-prefix"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str starts-with "a" "b"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with accepts exactly one prefix argument in eBPF"
    }
    {
        name: "core-string-starts-with-rejects-dynamic-non-string-input"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | str starts-with "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with requires tracked string input in eBPF"
    }
    {
        name: "core-string-starts-with-rejects-dynamic-prefix"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str starts-with $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with requires a compile-time string literal"
    }
    {
        name: "core-string-starts-with-rejects-list-item-type"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str starts-with "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-starts-with-rejects-nul-prefix"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str starts-with "\u{0}"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with does not support NUL bytes in the prefix in eBPF"
    }
    {
        name: "core-string-starts-with-rejects-ignore-case-runtime-input"
        category: "language-core"
        tags: [string str starts-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str starts-with --ignore-case "he"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str starts-with --ignore-case requires compile-time known string input in eBPF"
    }
]
