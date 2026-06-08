const VERIFIER_DIFF_FIXTURES_2368_2368 = [
    {
        name: "sockmap-map-get-rejects-socket-map-kind"
        category: "maps"
        tags: [maps sockmap map-get diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get active_sockmap --kind sockmap)'
            '  if $entry { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get is not supported for socket map kind sockmap"
    }
]
