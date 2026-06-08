const VERIFIER_DIFF_FIXTURES_2364_2364 = [
    {
        name: "arena-map-put-rejects-unmodeled-map-kind"
        category: "maps"
        tags: [maps arena map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put arena_values $ctx.pid --kind arena'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "arena map_extra/mmap support is not modeled yet"
    }
]
