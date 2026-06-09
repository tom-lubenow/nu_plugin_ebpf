const VERIFIER_DIFF_FIXTURES_3008_3012 = [
    {
        name: "core-user-function-rejects-subfunction-argument-limit"
        category: "language-core"
        tags: [user-functions diagnostics reject arguments]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  def foo [a b c d e f] { $a + $b + $c + $d + $e + $f }'
            '  foo 1 2 3 4 5 6'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "BPF subfunctions support at most 5 arguments"
    }
    {
        name: "core-pointer-arithmetic-rejects-numeric-minus-pointer"
        category: "language-core"
        tags: [pointer arithmetic diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  1 - $ctx.task'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "numeric - pointer is not supported"
    }
    {
        name: "tail-call-rejects-missing-index"
        category: "language-surface"
        tags: [tail-call diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  tail-call jumps'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tail-call requires a target index from pipeline input or a second positional argument"
    }
    {
        name: "tail-call-rejects-runtime-map-name"
        category: "language-surface"
        tags: [tail-call diagnostics reject runtime]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  0 | tail-call $ctx.comm'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "tail-call requires a compile-time string literal"
    }
    {
        name: "tail-call-rejects-existing-generic-map-name"
        category: "language-surface"
        tags: [tail-call maps diagnostics reject]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  map-define jumps --kind hash --key-type u32 --value-type u64'
            '  0 | tail-call jumps'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map 'jumps' conflicts with an existing map name"
    }
]
