const VERIFIER_DIFF_FIXTURES_3099_3099 = [
    {
        name: "core-describe-rejects-oversized-output"
        category: "language-core"
        tags: [describe diagnostics reject capacity record]
        target: "kprobe:ksys_read"
        program: [
            '{|ctx|'
            '  {'
            '    f0: 0'
            '    f1: 1'
            '    f2: 2'
            '    f3: 3'
            '    f4: 4'
            '    f5: 5'
            '    f6: 6'
            '    f7: 7'
            '    f8: 8'
            '    f9: 9'
            '    f10: 10'
            '    f11: 11'
            '    f12: 12'
            '    f13: 13'
            '    f14: 14'
            '  } | describe | str length'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "describe output is 146 bytes; eBPF lowering supports at most 127 bytes"
    }
]
