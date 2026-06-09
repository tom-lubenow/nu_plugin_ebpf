const VERIFIER_DIFF_FIXTURES_2497_2502 = [
    {
        name: "core-string-ends-with-rejects-extra-suffix"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str ends-with "c" "b"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with accepts exactly one suffix argument in eBPF"
    }
    {
        name: "core-string-ends-with-rejects-dynamic-non-string-input"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | str ends-with "a"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with requires tracked string input in eBPF"
    }
    {
        name: "core-string-ends-with-rejects-dynamic-suffix"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str ends-with $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with requires a compile-time string literal"
    }
    {
        name: "core-string-ends-with-rejects-list-item-type"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str ends-with "c"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-ends-with-rejects-nul-suffix"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str ends-with "\u{0}"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with does not support NUL bytes in the suffix in eBPF"
    }
    {
        name: "core-string-ends-with-rejects-ignore-case-runtime-input"
        category: "language-core"
        tags: [string str ends-with diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "hello" | global-define --type string:8 left'
            '  let left = (global-get left)'
            '  $left | str ends-with --ignore-case "LO"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str ends-with --ignore-case requires compile-time known string input in eBPF"
    }
]
