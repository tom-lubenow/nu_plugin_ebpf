const VERIFIER_DIFF_FIXTURES_2693_2704 = [
    {
        name: "core-seq-rejects-missing-arguments"
        category: "language-core"
        tags: [aggregate list seq diagnostics reject arity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq supports one to three numeric arguments in eBPF"
    }
    {
        name: "core-seq-rejects-extra-arguments"
        category: "language-core"
        tags: [aggregate list seq diagnostics reject arity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 2 3 4'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq supports one to three numeric arguments in eBPF"
    }
    {
        name: "core-seq-rejects-unfolded-float-output"
        category: "language-core"
        tags: [aggregate list seq diagnostics reject float]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1.0 0.5 2.0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq float output is supported only when folded by metadata consumers in eBPF"
    }
    {
        name: "core-seq-rejects-numeric-output-over-capacity"
        category: "language-core"
        tags: [aggregate list seq diagnostics reject capacity]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq 1 100'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq output exceeds stack-backed numeric list capacity 60 in eBPF"
    }
    {
        name: "core-seq-char-rejects-multi-character-argument"
        category: "language-core"
        tags: [aggregate list seq char diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq char aa b'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq char requires individual ASCII character arguments in eBPF"
    }
    {
        name: "core-seq-date-rejects-missing-begin-date"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject begin]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --end-date "2020-01-02"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date requires explicit --begin-date in eBPF"
    }
    {
        name: "core-seq-date-rejects-missing-end-condition"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject end]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date requires explicit --end-date, --days, or --periods in eBPF"
    }
    {
        name: "core-seq-date-rejects-nonpositive-increment"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject increment]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-02" --increment -1'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --increment requires a positive duration in eBPF"
    }
    {
        name: "core-seq-date-rejects-nonpositive-days"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject days]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --days 0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --days requires a positive integer in eBPF"
    }
    {
        name: "core-seq-date-rejects-dynamic-days"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject days dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --days $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --days requires a compile-time known integer in eBPF"
    }
    {
        name: "core-seq-date-rejects-dynamic-increment"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject increment dynamic]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --begin-date "2020-01-01" --end-date "2020-01-02" --increment $ctx.pid'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --increment requires a compile-time known integer day count or duration in eBPF"
    }
    {
        name: "core-seq-date-rejects-input-format-mismatch"
        category: "language-core"
        tags: [aggregate list seq date diagnostics reject format]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  seq date --input-format "%m/%d/%Y" --begin-date "2020-01-01" --end-date "2020-01-02"'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "seq date --begin-date does not match --input-format '%m/%d/%Y' in eBPF"
    }
]
