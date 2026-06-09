const VERIFIER_DIFF_FIXTURES_2987_2991 = [
    {
        name: "core-string-screaming-snake-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str screaming-snake-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str screaming-snake-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str screaming-snake-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-screaming-snake-case-rejects-list-item-type"
        category: "language-core"
        tags: [string str screaming-snake-case diagnostics reject list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  ["ab cd" 1] | str screaming-snake-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str screaming-snake-case requires string list items in eBPF; item 1 has type int"
    }
    {
        name: "core-string-title-case-rejects-dynamic-input"
        category: "language-core"
        tags: [string str title-case diagnostics reject input dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | str title-case'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str title-case requires compile-time known string input in eBPF"
    }
    {
        name: "core-string-str-expand-rejects-result-capacity"
        category: "language-core"
        tags: [string str expand diagnostics reject capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{1,2,3,4,5,6,7,8}{a,b,c,d,e,f,g,h}" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand produced 61 strings; eBPF lowering supports at most 60"
    }
    {
        name: "core-string-str-expand-rejects-output-capacity"
        category: "language-core"
        tags: [string str expand diagnostics reject capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{b,c}" | str expand'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "str expand output requires 129 bytes (limit 128)"
    }
]
