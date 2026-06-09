const VERIFIER_DIFF_FIXTURES_2387_2387 = [
    {
        name: "arena-map-delete-rejects-unmodeled-kind"
        category: "maps"
        tags: [maps arena map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete arena_map --kind arena'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind arena names an arena map"
    }
]
