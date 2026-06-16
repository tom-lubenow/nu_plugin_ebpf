const VERIFIER_DIFF_FIXTURES_1688_1718_B_C = [
    {
        name: "core-list-math-sum"
        category: "language-core"
        tags: [aggregate list math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [10 20 30] | math sum'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-integer-sum"
        category: "language-core"
        tags: [aggregate list seq math sum]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  (seq 1 5 | math sum) == 15'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "core-seq-negative-step-join"
        category: "language-core"
        tags: [aggregate list seq str join]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 5 -2 1 | str join "-" | str starts-with "5-3-1"'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
