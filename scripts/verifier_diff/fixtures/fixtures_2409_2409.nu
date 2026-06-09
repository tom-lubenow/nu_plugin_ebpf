const VERIFIER_DIFF_FIXTURES_2409_2409 = [
    {
        name: "struct-ops-map-define-rejects-kind"
        category: "maps"
        tags: [maps struct-ops map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ops --kind struct-ops'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind struct-ops is reserved for struct_ops objects"
    }
]
