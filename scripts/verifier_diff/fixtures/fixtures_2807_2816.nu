const VERIFIER_DIFF_FIXTURES_2807_2816 = [
    {
        name: "core-match-rejects-list-pattern"
        category: "language-core"
        tags: [match diagnostics reject list pattern]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { [a b] => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Pattern matching not supported in eBPF: List"
    }
    {
        name: "core-match-rejects-record-pattern"
        category: "language-core"
        tags: [match diagnostics reject record pattern]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { {pid: x} => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Pattern matching not supported in eBPF: Record"
    }
    {
        name: "core-match-range-rejects-expression-start"
        category: "language-core"
        tags: [match range diagnostics reject start]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.uid { (0 + 1)..10 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range patterns require a literal integer start in eBPF"
    }
    {
        name: "core-match-range-rejects-expression-end"
        category: "language-core"
        tags: [match range diagnostics reject end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.uid { 0..(10 + 1) => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range patterns require a literal integer end in eBPF"
    }
    {
        name: "core-match-range-rejects-expression-next"
        category: "language-core"
        tags: [match range diagnostics reject step]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.uid { 0..(1 + 1)..10 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range patterns require a literal integer next value in eBPF"
    }
    {
        name: "core-match-range-rejects-zero-step"
        category: "language-core"
        tags: [match range diagnostics reject zero]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { 1..1..10 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range patterns require a non-zero explicit step in eBPF"
    }
    {
        name: "core-match-range-rejects-overflowing-step"
        category: "language-core"
        tags: [match range diagnostics reject overflow]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { -9223372036854775808..0..1 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match range pattern step overflows i64 in eBPF"
    }
    {
        name: "core-match-rejects-subexpression-pattern"
        category: "language-core"
        tags: [match diagnostics reject subexpression]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { (1 + 1) => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match against expression pattern FullCellPath"
    }
    {
        name: "core-match-rejects-float-pattern"
        category: "language-core"
        tags: [match diagnostics reject float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { 1.5 => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match against expression pattern Float(1.5) not supported in eBPF"
    }
    {
        name: "core-match-rejects-binary-pattern"
        category: "language-core"
        tags: [match diagnostics reject binary]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  match $ctx.pid { 0x[01] => 1, _ => 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "Match against expression pattern Binary([1]) not supported in eBPF"
    }
]
