const VERIFIER_DIFF_FIXTURES_2407_2407 = [
    {
        name: "prog-array-map-define-rejects-tail-call-map-kind"
        category: "maps"
        tags: [maps prog-array map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define jumps --kind prog-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind prog-array is reserved for program-array maps"
    }
]
