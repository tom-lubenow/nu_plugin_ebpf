const VERIFIER_DIFF_FIXTURES_2362_2362 = [
    {
        name: "struct-ops-map-put-rejects-kind"
        category: "maps"
        tags: [maps struct-ops map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put ops $ctx.pid --kind struct-ops'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reserved for struct_ops objects"
    }
]
