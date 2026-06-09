const VERIFIER_DIFF_FIXTURES_2571_2578 = [
    {
        name: "core-string-str-downcase-rejects-cell-path-argument"
        category: "language-core"
        tags: [string str downcase diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "AbC" | str downcase name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str downcase currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-str-downcase-rejects-dynamic-input"
        category: "language-core"
        tags: [string str downcase diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str downcase'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str downcase requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-downcase-rejects-list-item-type"
        category: "language-core"
        tags: [string str downcase diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["Ab" 1] | str downcase'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str downcase requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-str-upcase-rejects-cell-path-argument"
        category: "language-core"
        tags: [string str upcase diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str upcase name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str upcase currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-str-reverse-rejects-dynamic-input"
        category: "language-core"
        tags: [string str reverse diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str reverse requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-title-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str title-case diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["nu shell" 1] | str title-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str title-case requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-describe-rejects-detailed-flag"
        category: "language-core"
        tags: [describe diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | describe --detailed'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "describe does not accept arguments in eBPF"
    }
    {
        name: "core-describe-rejects-untracked-context-root"
        category: "language-core"
        tags: [describe diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx | describe'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "describe requires compiler-tracked input in eBPF"
    }
]
