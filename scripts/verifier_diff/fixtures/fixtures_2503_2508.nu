const VERIFIER_DIFF_FIXTURES_2503_2508 = [
    {
        name: "core-string-contains-rejects-extra-substring"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str contains "a" "b"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains accepts exactly one substring argument in eBPF"
    }
    {
        name: "core-string-contains-rejects-dynamic-non-string-input"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | str contains "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains requires tracked string input in eBPF"
    }
    {
        name: "core-string-contains-rejects-dynamic-substring"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str contains $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains requires a compile-time string literal"
    }
    {
        name: "core-string-contains-rejects-list-item-type"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str contains "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-contains-rejects-nul-substring"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str contains "\u{0}"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains does not support NUL bytes in the substring in eBPF"
    }
    {
        name: "core-string-contains-rejects-ignore-case-runtime-input"
        category: "language-core"
        tags: [string str contains diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str contains --ignore-case "LL"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str contains --ignore-case requires compile-time known string input in eBPF"
    }
]
