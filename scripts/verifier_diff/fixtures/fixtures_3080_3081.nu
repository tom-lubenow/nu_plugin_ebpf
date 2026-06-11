const VERIFIER_DIFF_FIXTURES_3080_3081 = [
    {
        name: "core-math-median-rejects-even-runtime-list"
        category: "language-core"
        tags: [math median diagnostics reject list runtime even]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  [20] | append $n | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median requires an odd-length stack-backed numeric list in eBPF because even-length medians are floats in Nushell"
    }
    {
        name: "core-math-median-rejects-large-runtime-list"
        category: "language-core"
        tags: [math median diagnostics reject list runtime capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  let n = random int'
            '  seq 1 1 16 | append $n | math median'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math median supports stack-backed numeric lists with known odd length <= 16 in eBPF"
    }
]
