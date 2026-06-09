const VERIFIER_DIFF_FIXTURES_3084_3085 = [
    {
        name: "core-math-abs-rejects-output-capacity"
        category: "language-core"
        tags: [math abs diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [-1 -2 -3 -4 -5 -6 -7 -8 -9 -10 -11 -12 -13 -14 -15 -16 -17 -18 -19 -20 -21 -22 -23 -24 -25 -26 -27 -28 -29 -30 -31 -32 -33 -34 -35 -36 -37 -38 -39 -40 -41 -42 -43 -44 -45 -46 -47 -48 -49 -50 -51 -52 -53 -54 -55 -56 -57 -58 -59 -60 -61] | math abs | length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math abs output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-math-avg-rejects-non-finite-result"
        category: "language-core"
        tags: [math avg diagnostics reject list float finite]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1e308 1e308] | math avg | fill --alignment right --character "0" --width 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "math avg compile-time list result must be finite in eBPF"
    }
]
