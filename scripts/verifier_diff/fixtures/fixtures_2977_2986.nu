const VERIFIER_DIFF_FIXTURES_2977_2986 = [
    {
        name: "core-string-reverse-rejects-argument"
        category: "language-core"
        tags: [string str reverse diagnostics reject argument]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | str reverse name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str reverse currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-camel-case-rejects-argument"
        category: "language-core"
        tags: [string str camel-case diagnostics reject argument]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab cd" | str camel-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str camel-case currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-pascal-case-rejects-argument"
        category: "language-core"
        tags: [string str pascal-case diagnostics reject argument]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab cd" | str pascal-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str pascal-case currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-snake-case-rejects-argument"
        category: "language-core"
        tags: [string str snake-case diagnostics reject argument]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "ab cd" | str snake-case name'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str snake-case currently supports only the default no-argument form in eBPF"
    }
    {
        name: "core-string-upcase-rejects-dynamic-input"
        category: "language-core"
        tags: [string str upcase diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str upcase'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str upcase requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-upcase-rejects-list-item-type"
        category: "language-core"
        tags: [string str upcase diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" 1] | str upcase'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str upcase requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-reverse-rejects-list-item-type"
        category: "language-core"
        tags: [string str reverse diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab" 1] | str reverse'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str reverse requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-pascal-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str pascal-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str pascal-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str pascal-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-kebab-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str kebab-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str kebab-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str kebab-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-kebab-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str kebab-case diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab cd" 1] | str kebab-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str kebab-case requires string list items in eBPF; item 1 has type int"
    }
]
