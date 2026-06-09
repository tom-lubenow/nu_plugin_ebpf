const VERIFIER_DIFF_FIXTURES_2917_2926 = [
    {
        name: "core-bits-or-rejects-dynamic-endian"
        category: "language-core"
        tags: [bits or binary endian diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits or --endian $ctx.comm 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or --endian requires a compile-time string literal"
    }
    {
        name: "core-bits-xor-rejects-dynamic-endian"
        category: "language-core"
        tags: [bits xor binary endian diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits xor --endian $ctx.comm 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor --endian requires a compile-time string literal"
    }
    {
        name: "core-bits-or-rejects-binary-input-integer-target"
        category: "language-core"
        tags: [bits or binary diagnostics reject target]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits or 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires a compile-time binary target argument for binary input in eBPF"
    }
    {
        name: "core-bits-xor-rejects-binary-list-dynamic-target"
        category: "language-core"
        tags: [bits xor binary diagnostics reject target list dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02]] | bits xor $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires a compile-time binary target argument for binary-list input in eBPF"
    }
    {
        name: "core-bits-shr-rejects-large-binary-count"
        category: "language-core"
        tags: [bits shr binary diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shr 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires a shift count from 0 through 8 for binary input in eBPF; got 9"
    }
    {
        name: "core-bits-rol-rejects-large-binary-count"
        category: "language-core"
        tags: [bits rol binary diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits rol 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires a rotate count from 0 through 8 for binary input in eBPF; got 9"
    }
    {
        name: "core-bits-shr-rejects-negative-binary-count"
        category: "language-core"
        tags: [bits shr binary diagnostics reject count negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shr -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires a non-negative shift count in eBPF; got -1"
    }
    {
        name: "core-bits-shl-rejects-negative-binary-count"
        category: "language-core"
        tags: [bits shl binary diagnostics reject count negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shl -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires a non-negative shift count in eBPF; got -1"
    }
    {
        name: "core-bits-ror-rejects-negative-binary-count"
        category: "language-core"
        tags: [bits ror binary diagnostics reject count negative]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits ror -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires a non-negative rotate count in eBPF; got -1"
    }
    {
        name: "core-bits-shr-rejects-large-auto-count"
        category: "language-core"
        tags: [bits shr diagnostics reject count]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shr 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires a shift count from 0 through 7 in eBPF; got 8"
    }
]
