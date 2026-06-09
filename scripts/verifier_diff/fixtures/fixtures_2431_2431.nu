const VERIFIER_DIFF_FIXTURES_2431_2431 = [
    {
        name: "map-put-rejects-declared-value-type-conflict"
        category: "maps"
        tags: [maps map-define map-put schema diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind array --value-type u64 --max-entries 4'
            '  { pid: $ctx.pid } | map-put seen 0 --kind array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put value type for 'seen' conflicts with declared map schema"
    }
]
