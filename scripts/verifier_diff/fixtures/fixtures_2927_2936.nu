const VERIFIER_DIFF_FIXTURES_2927_2936 = [
    {
        name: "core-bits-shl-rejects-negative-auto-count"
        category: "language-core"
        tags: [bits shl diagnostics reject count negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shl -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires a shift count from 0 through 7 in eBPF; got -1"
    }
    {
        name: "core-bits-rol-rejects-large-auto-count"
        category: "language-core"
        tags: [bits rol diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits rol 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires a rotate count from 0 through 8 in eBPF; got 9"
    }
    {
        name: "core-bits-or-rejects-binary-target-for-mixed-list"
        category: "language-core"
        tags: [bits or diagnostics reject target binary list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bits or 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires integer target argument in eBPF; got MIR type Array { elem: U8, len: 1 }"
    }
    {
        name: "core-bits-xor-rejects-binary-target-for-mixed-list"
        category: "language-core"
        tags: [bits xor diagnostics reject target binary list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 1] | bits xor 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires integer target argument in eBPF; got MIR type Array { elem: U8, len: 1 }"
    }
    {
        name: "core-bits-not-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits not diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-or-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits or diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits or 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-xor-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits xor diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits xor 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-shl-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits shl diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-shr-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits shr diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits shr 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-rol-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits rol diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
]
