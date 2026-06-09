const VERIFIER_DIFF_FIXTURES_2907_2916 = [
    {
        name: "core-bits-or-rejects-missing-input"
        category: "language-core"
        tags: [bits or diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits or 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-xor-rejects-missing-input"
        category: "language-core"
        tags: [bits xor diagnostics reject input]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  bits xor 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires integer, binary, integer-list, or binary-list pipeline input in eBPF"
    }
    {
        name: "core-bits-or-rejects-string-input"
        category: "language-core"
        tags: [bits or diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bits or 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires integer pipeline input in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-xor-rejects-string-input"
        category: "language-core"
        tags: [bits xor diagnostics reject input string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  $ctx.comm | bits xor 1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires integer pipeline input in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-or-rejects-string-target"
        category: "language-core"
        tags: [bits or diagnostics reject target string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits or $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires integer target argument in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-xor-rejects-string-target"
        category: "language-core"
        tags: [bits xor diagnostics reject target string]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits xor $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires integer target argument in eBPF; got MIR type Array { elem: U8, len: 16 }"
    }
    {
        name: "core-bits-or-rejects-binary-target-integer-input"
        category: "language-core"
        tags: [bits or diagnostics reject target binary]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits or 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires binary pipeline input when the target argument is binary in eBPF"
    }
    {
        name: "core-bits-xor-rejects-binary-target-integer-input"
        category: "language-core"
        tags: [bits xor diagnostics reject target binary]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 | bits xor 0x[01]'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires binary pipeline input when the target argument is binary in eBPF"
    }
    {
        name: "core-bits-or-rejects-dynamic-list-target"
        category: "language-core"
        tags: [bits or diagnostics reject target dynamic list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits or $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits or requires a compile-time integer target argument for compile-time known list input in eBPF"
    }
    {
        name: "core-bits-xor-rejects-dynamic-list-target"
        category: "language-core"
        tags: [bits xor diagnostics reject target dynamic list]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  [1 2] | bits xor $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "bits xor requires a compile-time integer target argument for compile-time known list input in eBPF"
    }
]
