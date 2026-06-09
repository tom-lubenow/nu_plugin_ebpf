const VERIFIER_DIFF_FIXTURES_2629_2639 = [
    {
        name: "core-bits-shl-rejects-dynamic-number-bytes"
        category: "language-core"
        tags: [bits shl diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shl --number-bytes $ctx.pid 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires compile-time --number-bytes in eBPF"
    }
    {
        name: "core-bits-shr-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits shr diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shr --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-shl-rejects-runtime-auto-width-large-count"
        category: "language-core"
        tags: [bits shl diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bits shl 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl default auto-width runtime shifts support shift counts from 0 through 7 in eBPF; got 8"
    }
    {
        name: "core-bits-shr-rejects-runtime-auto-width-large-count"
        category: "language-core"
        tags: [bits shr diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bits shr 8'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr default auto-width runtime shifts support shift counts from 0 through 7 in eBPF; got 8"
    }
    {
        name: "core-bits-shl-unsigned-u32-rejects-unsafe-runtime-count"
        category: "language-core"
        tags: [bits shl diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bits shl --number-bytes 8 32'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl unsigned --number-bytes 8 runtime u32 input supports shift counts from 0 through 31 in eBPF; got 32"
    }
    {
        name: "core-bits-rol-unsigned-u32-rejects-unsafe-runtime-count"
        category: "language-core"
        tags: [bits rol diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bits rol --number-bytes 8 32'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol unsigned --number-bytes 8 runtime u32 input supports rotate counts from 0 through 31, or 64, in eBPF; got 32"
    }
    {
        name: "core-bits-ror-rejects-dynamic-rotate-count"
        category: "language-core"
        tags: [bits ror diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits ror $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires a compile-time integer rotate count in eBPF"
    }
    {
        name: "core-bits-ror-binary-rejects-large-rotate-count"
        category: "language-core"
        tags: [bits ror binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits ror 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires a rotate count from 0 through 8 for binary input in eBPF; got 9"
    }
    {
        name: "core-bits-rol-binary-rejects-negative-rotate-count"
        category: "language-core"
        tags: [bits rol binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits rol -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires a non-negative rotate count in eBPF; got -1"
    }
    {
        name: "core-bits-and-rejects-int-input-binary-target"
        category: "language-core"
        tags: [bits and binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits and 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and requires binary pipeline input when the target argument is binary in eBPF"
    }
    {
        name: "core-bits-or-rejects-binary-list-integer-target"
        category: "language-core"
        tags: [bits or binary list diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01]] | bits or 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires a compile-time binary target argument for binary-list input in eBPF"
    }
]
