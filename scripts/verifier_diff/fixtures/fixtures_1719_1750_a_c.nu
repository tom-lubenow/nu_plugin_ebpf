const VERIFIER_DIFF_FIXTURES_1719_1750_A_C = [
    {
        name: "core-list-math-product"
        category: "language-core"
        tags: [aggregate list math product]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [2 3 4] | math product'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-min"
        category: "language-core"
        tags: [aggregate list math min]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math min'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-list-math-max"
        category: "language-core"
        tags: [aggregate list math max]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [20 10 30] | math max'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
