const VERIFIER_DIFF_FIXTURES_2757_2766 = [
    {
        name: "core-string-capitalize-rejects-cell-path-on-scalar-input"
        category: "language-core"
        tags: [string str capitalize diagnostics reject cell-path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str capitalize name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str capitalize cell-path arguments require compile-time known record or table input in eBPF; input has type string"
    }
    {
        name: "core-string-capitalize-rejects-dynamic-input"
        category: "language-core"
        tags: [string str capitalize diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str capitalize'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str capitalize requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-camel-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str camel-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str camel-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str camel-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-camel-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str camel-case diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab cd" 1] | str camel-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str camel-case requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-kebab-case-rejects-cell-path-on-scalar-input"
        category: "language-core"
        tags: [string str kebab-case diagnostics reject cell-path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcDef" | str kebab-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str kebab-case cell-path arguments require compile-time known record or table input in eBPF; input has type string"
    }
    {
        name: "core-string-pascal-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str pascal-case diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab cd" 1] | str pascal-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str pascal-case requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-screaming-snake-case-rejects-cell-path-on-scalar-input"
        category: "language-core"
        tags: [string str screaming-snake-case diagnostics reject cell-path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abcDef" | str screaming-snake-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str screaming-snake-case cell-path arguments require compile-time known record or table input in eBPF; input has type string"
    }
    {
        name: "core-string-snake-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str snake-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str snake-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str snake-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-snake-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str snake-case diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["NuShell" 1] | str snake-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str snake-case requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-title-case-rejects-cell-path-on-scalar-input"
        category: "language-core"
        tags: [string str title-case diagnostics reject cell-path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "nu shell" | str title-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str title-case cell-path arguments require compile-time known record or table input in eBPF; input has type string"
    }
]
