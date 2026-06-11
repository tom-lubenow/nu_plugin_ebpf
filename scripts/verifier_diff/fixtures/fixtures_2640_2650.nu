const VERIFIER_DIFF_FIXTURES_2640_2650 = [
    {
        name: "core-bits-and-rejects-dynamic-endian"
        category: "language-core"
        tags: [bits and binary endian diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits and --endian $ctx.comm 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and --endian requires a compile-time string literal"
    }
    {
        name: "core-bits-xor-rejects-binary-input-integer-target"
        category: "language-core"
        tags: [bits xor binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits xor 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires a compile-time binary target argument for binary input in eBPF"
    }
    {
        name: "core-bits-not-rejects-string-input"
        category: "language-core"
        tags: [bits not diagnostics reject type]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  "abc" | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Command does not support string input"
    }
    {
        name: "core-bits-shr-rejects-negative-shift-count"
        category: "language-core"
        tags: [bits shr diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shr -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires a shift count from 0 through 7 in eBPF; got -1"
    }
    {
        name: "core-bits-ror-rejects-large-u8-rotate-count"
        category: "language-core"
        tags: [bits ror diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits ror --number-bytes 1 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires a rotate count from 0 through 8 in eBPF; got 9"
    }
    {
        name: "core-bits-shl-unsigned-u64-rejects-output-overflow"
        category: "language-core"
        tags: [bits shl diagnostics reject overflow]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  4611686018427387904 | bits shl --number-bytes 8 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl unsigned 8-byte output exceeds Nushell's integer range in eBPF"
    }
    {
        name: "core-bits-ror-unsigned-u64-rejects-output-overflow"
        category: "language-core"
        tags: [bits ror diagnostics reject overflow]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits ror --number-bytes 8 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror unsigned 8-byte output exceeds Nushell's integer range in eBPF"
    }
    {
        name: "core-bits-shl-unsigned-u64-rejects-runtime-list"
        category: "language-core"
        tags: [bits shl diagnostics reject runtime list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [(random int)] | bits shl --number-bytes 8 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 scalar input in eBPF"
    }
    {
        name: "core-bits-rol-unsigned-u64-rejects-runtime-list"
        category: "language-core"
        tags: [bits rol diagnostics reject runtime list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [(random int)] | bits rol --number-bytes 8 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol unsigned --number-bytes 8 requires compile-time known integer input or runtime u8, u16, or u32 scalar input for safe bits rol counts in eBPF"
    }
    {
        name: "core-bits-and-rejects-large-numeric-list-output"
        category: "language-core"
        tags: [bits and diagnostics reject list capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61] | bits and 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-bits-not-rejects-empty-binary-list-output"
        category: "language-core"
        tags: [bits not binary list diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[] 0x[01]] | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not binary list output requires non-empty equal-length binary items in eBPF"
    }
]
