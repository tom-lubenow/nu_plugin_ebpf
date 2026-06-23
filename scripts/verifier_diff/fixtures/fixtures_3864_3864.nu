export const VERIFIER_DIFF_FIXTURES_3864_3864 = [
    {
        name: "bloom-filter-map-put-rejects-non-update-kind"
        category: "maps"
        tags: [maps bloom-filter map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put recent_pids 0 --kind bloom-filter'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-push to insert values and map-contains --kind bloom-filter"
    }
]
