const VERIFIER_DIFF_FIXTURES_2747_2756 = [
    {
        name: "core-bits-shr-rejects-missing-input"
        category: "language-core"
        tags: [bits shr diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits shr 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-shr-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits shr diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits shr 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr requires integer list items in eBPF; item 1 has type string"
    }
    {
        name: "core-bits-shr-rejects-unequal-binary-list-output"
        category: "language-core"
        tags: [bits shr binary list diagnostics reject output]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits shr 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shr binary list output requires non-empty equal-length binary items in eBPF"
    }
    {
        name: "core-bits-rol-rejects-missing-input"
        category: "language-core"
        tags: [bits rol diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-rol-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits rol diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol requires integer list items in eBPF; item 1 has type string"
    }
    {
        name: "core-bits-rol-rejects-unequal-binary-list-output"
        category: "language-core"
        tags: [bits rol binary list diagnostics reject output]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits rol 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits rol binary list output requires non-empty equal-length binary items in eBPF"
    }
    {
        name: "core-bits-ror-rejects-missing-input"
        category: "language-core"
        tags: [bits ror diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-ror-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits ror diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires integer list items in eBPF; item 1 has type string"
    }
    {
        name: "core-bits-ror-rejects-unequal-binary-list-output"
        category: "language-core"
        tags: [bits ror binary list diagnostics reject output]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror binary list output requires non-empty equal-length binary items in eBPF"
    }
    {
        name: "core-bits-not-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits not diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not requires integer list items in eBPF; item 1 has type string"
    }
]
