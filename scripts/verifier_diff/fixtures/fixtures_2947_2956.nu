const VERIFIER_DIFF_FIXTURES_2947_2956 = [
    {
        name: "core-bits-shl-binary-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits shl binary diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shl --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl supports only --signed and --number-bytes for binary input in eBPF"
    }
    {
        name: "core-bits-shr-binary-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits shr binary diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shr --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr supports only --signed and --number-bytes for binary input in eBPF"
    }
    {
        name: "core-bits-rol-binary-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits rol binary diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits rol --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol supports only --signed and --number-bytes for binary input in eBPF"
    }
    {
        name: "core-bits-ror-binary-rejects-duplicate-signed-flag"
        category: "language-core"
        tags: [bits ror binary diagnostics reject flags]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits ror --signed --signed 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror supports only --signed and --number-bytes for binary input in eBPF"
    }
    {
        name: "core-bits-or-rejects-invalid-endian"
        category: "language-core"
        tags: [bits or binary diagnostics reject endian]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits or --endian middle 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: 'bits or --endian supports only native, little, or big in eBPF; got "middle"'
    }
    {
        name: "core-bits-xor-rejects-invalid-endian"
        category: "language-core"
        tags: [bits xor binary diagnostics reject endian]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits xor --endian middle 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: 'bits xor --endian supports only native, little, or big in eBPF; got "middle"'
    }
    {
        name: "core-bits-shl-binary-rejects-empty-input-count"
        category: "language-core"
        tags: [bits shl binary diagnostics reject count empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires a shift count from 0 through 0 for binary input in eBPF; got 1"
    }
    {
        name: "core-bits-shr-binary-rejects-empty-input-count"
        category: "language-core"
        tags: [bits shr binary diagnostics reject count empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bits shr 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires a shift count from 0 through 0 for binary input in eBPF; got 1"
    }
    {
        name: "core-bits-rol-binary-rejects-empty-input-count"
        category: "language-core"
        tags: [bits rol binary diagnostics reject count empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires a rotate count from 0 through 0 for binary input in eBPF; got 1"
    }
    {
        name: "core-bits-ror-binary-rejects-empty-input-count"
        category: "language-core"
        tags: [bits ror binary diagnostics reject count empty]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[] | bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires a rotate count from 0 through 0 for binary input in eBPF; got 1"
    }
]
