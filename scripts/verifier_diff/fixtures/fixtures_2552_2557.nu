const VERIFIER_DIFF_FIXTURES_2552_2557 = [
    {
        name: "core-string-str-replace-rejects-cell-path-on-scalar-input"
        category: "language-core"
        tags: [string str replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str replace "a" "b" name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str replace cell-path arguments require compile-time known record or table input in eBPF; input has type string"
    }
    {
        name: "core-string-str-replace-rejects-dynamic-find"
        category: "language-core"
        tags: [string str replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str replace $ctx.comm "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str replace find requires a compile-time string literal"
    }
    {
        name: "core-string-str-replace-rejects-dynamic-replacement"
        category: "language-core"
        tags: [string str replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str replace "a" $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str replace replacement requires a compile-time string literal"
    }
    {
        name: "core-string-str-replace-accepts-context-comm-input"
        category: "language-core"
        tags: [string str replace length accept runtime context]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (($ctx.comm | str replace "a" "b" | str length) >= 0)'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-str-replace-rejects-list-item-type"
        category: "language-core"
        tags: [string str replace diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["abc" 1] | str replace "a" "b"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str replace requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-str-replace-rejects-invalid-regex"
        category: "language-core"
        tags: [string str replace regex diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str replace --regex "[" "x"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str replace --regex pattern is invalid in eBPF"
    }
]
