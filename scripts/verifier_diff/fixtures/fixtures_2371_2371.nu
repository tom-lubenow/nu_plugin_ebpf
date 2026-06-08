const VERIFIER_DIFF_FIXTURES_2371_2371 = [
    {
        name: "bloom-filter-map-get-rejects-non-lookup-kind"
        category: "maps"
        tags: [maps bloom-filter map-get diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get recent_pids --kind bloom-filter)'
            '  if $entry { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind bloom-filter is not a lookup map"
    }
]
