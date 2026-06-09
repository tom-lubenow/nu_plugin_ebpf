const VERIFIER_DIFF_FIXTURES_2411_2411 = [
    {
        name: "arena-map-define-rejects-unmodeled-kind"
        category: "maps"
        tags: [maps arena map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define arena_space --kind arena'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind arena names an arena map"
    }
]
