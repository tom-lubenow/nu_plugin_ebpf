const VERIFIER_DIFF_FIXTURES_2354_2354 = [
    {
        name: "stack-trace-map-delete-rejects-kind"
        category: "maps"
        tags: [maps stack-trace map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete stacks --kind stack-trace'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use ctx.kstack/ctx.ustack or modeled stack helpers"
    }
]
