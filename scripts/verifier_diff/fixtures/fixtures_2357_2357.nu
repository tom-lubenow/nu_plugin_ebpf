const VERIFIER_DIFF_FIXTURES_2357_2357 = [
    {
        name: "queue-map-put-rejects-kind"
        category: "maps"
        tags: [maps queue map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put recent_args 0 --kind queue'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put is not supported for map kind"
    }
]
