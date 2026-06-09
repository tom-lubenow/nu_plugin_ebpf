const VERIFIER_DIFF_FIXTURES_2937_2946 = [
    {
        name: "core-bits-shl-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits shl diagnostics reject flags integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shl --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl supports only --signed and --number-bytes for integer input in eBPF"
    }
    {
        name: "core-bits-shr-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits shr diagnostics reject flags integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shr --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr supports only --signed and --number-bytes for integer input in eBPF"
    }
    {
        name: "core-bits-rol-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits rol diagnostics reject flags integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits rol --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol supports only --signed and --number-bytes for integer input in eBPF"
    }
    {
        name: "core-bits-ror-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits ror diagnostics reject flags integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits ror --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror supports only --signed and --number-bytes for integer input in eBPF"
    }
    {
        name: "core-bits-ror-rejects-invalid-integer-number-bytes"
        category: "language-core"
        tags: [bits ror diagnostics reject number-bytes integer]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits ror --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-shl-binary-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits shl binary diagnostics reject number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shl --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-shr-binary-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits shr binary diagnostics reject number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shr --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-rol-binary-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits rol binary diagnostics reject number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits rol --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-ror-binary-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits ror binary diagnostics reject number-bytes]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits ror --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-ror-rejects-oversized-list-output"
        category: "language-core"
        tags: [bits ror diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
]
