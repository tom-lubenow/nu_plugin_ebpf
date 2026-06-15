const VERIFIER_DIFF_FIXTURES_1969_2000_B_C = [
    {
        name: "core-string-expand-length"
        category: "language-core"
        tags: [string str expand list length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-path-length"
        category: "language-core"
        tags: [string str expand list length path]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "C:\\{Users,Windows}" | str expand --path | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-empty-length"
        category: "language-core"
        tags: [string str expand list length empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{2..1}B" | str expand | length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-length"
        category: "language-core"
        tags: [string str expand list get length]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 0 | str length'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{b,c}D{e,f}G" | str expand | get 1 | str starts-with "AbDfG"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-string-expand-range-get-content"
        category: "language-core"
        tags: [string str expand list get starts-with range]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "A{08..10}B" | str expand | get 2 | str starts-with "A10B"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
