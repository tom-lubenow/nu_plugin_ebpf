const VERIFIER_DIFF_FIXTURES_2737_2746 = [
    {
        name: "core-bits-not-rejects-missing-input"
        category: "language-core"
        tags: [bits not diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits not'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits not requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-shl-rejects-missing-input"
        category: "language-core"
        tags: [bits shl diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-and-rejects-string-target"
        category: "language-core"
        tags: [bits and diagnostics reject target string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits and $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and requires integer target argument in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-and-rejects-string-input"
        category: "language-core"
        tags: [bits and diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bits and 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and requires integer pipeline input in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-shl-rejects-string-input"
        category: "language-core"
        tags: [bits shl diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires integer pipeline input in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-ror-rejects-string-input"
        category: "language-core"
        tags: [bits ror diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bits ror 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits ror requires integer pipeline input in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-xor-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits xor diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits xor 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires integer list items in eBPF; item 1 has type string"
    }
    {
        name: "core-bits-shl-rejects-mixed-numeric-list"
        category: "language-core"
        tags: [bits shl diagnostics reject list string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 "x"] | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl requires integer list items in eBPF; item 1 has type string"
    }
    {
        name: "core-bits-and-rejects-unequal-binary-list-output"
        category: "language-core"
        tags: [bits and binary list diagnostics reject output]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits and 0x[ff]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits and binary list output requires non-empty equal-length binary items in eBPF"
    }
    {
        name: "core-bits-shl-rejects-unequal-binary-list-output"
        category: "language-core"
        tags: [bits shl binary list diagnostics reject output]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [0x[01] 0x[02 03]] | bits shl 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits shl binary list output requires non-empty equal-length binary items in eBPF"
    }
]
