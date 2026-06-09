const VERIFIER_DIFF_FIXTURES_2406_2406 = [
    {
        name: "stack-trace-map-define-rejects-stack-map-kind"
        category: "maps"
        tags: [maps stack-trace map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define stacks --kind stack-trace'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind stack-trace is reserved for stack-trace maps"
    }
]
