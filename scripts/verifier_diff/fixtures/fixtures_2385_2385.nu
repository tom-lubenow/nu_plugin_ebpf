const VERIFIER_DIFF_FIXTURES_2385_2385 = [
    {
        name: "struct-ops-map-delete-rejects-attach-kind"
        category: "maps"
        tags: [maps struct-ops map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete ops --kind struct-ops'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind struct-ops is reserved for struct_ops objects"
    }
]
