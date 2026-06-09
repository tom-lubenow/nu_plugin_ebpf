const VERIFIER_DIFF_FIXTURES_2618_2628 = [
    {
        name: "core-bits-not-rejects-dynamic-number-bytes"
        category: "language-core"
        tags: [bits not diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits not --number-bytes $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not requires compile-time --number-bytes in eBPF"
    }
    {
        name: "core-bits-not-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits not diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits not --number-bytes 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not masked integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-not-signed-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits not signed diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits not --signed --number-bytes 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not --signed supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-not-binary-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits not binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[ff] | bits not --number-bytes 3'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not binary input supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-and-binary-rejects-invalid-endian"
        category: "language-core"
        tags: [bits and binary endian diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits and --endian middle 0x[02]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: 'bits and --endian supports only native, little, or big in eBPF; got "middle"'
    }
    {
        name: "core-bits-shl-rejects-dynamic-shift-count"
        category: "language-core"
        tags: [bits shl diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shl $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires a compile-time integer shift count in eBPF"
    }
    {
        name: "core-bits-shl-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits shl diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits shl --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-rol-rejects-dynamic-rotate-count"
        category: "language-core"
        tags: [bits rol diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits rol $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires a compile-time integer rotate count in eBPF"
    }
    {
        name: "core-bits-rol-rejects-invalid-number-bytes"
        category: "language-core"
        tags: [bits rol diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits rol --number-bytes 3 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol integer mode supports --number-bytes 1, 2, 4, or 8 in eBPF; got 3"
    }
    {
        name: "core-bits-shl-binary-rejects-large-shift-count"
        category: "language-core"
        tags: [bits shl binary diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0x[01] | bits shl 9'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires a shift count from 0 through 8 for binary input in eBPF; got 9"
    }
    {
        name: "core-bits-ror-unsigned-u32-rejects-unsafe-runtime-count"
        category: "language-core"
        tags: [bits ror diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.pid | bits ror --number-bytes 8 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror unsigned --number-bytes 8 runtime u32 input supports rotate counts 0, or from 33 through 64, in eBPF; got 1"
    }
]
