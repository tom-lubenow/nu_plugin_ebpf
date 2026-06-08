const VERIFIER_DIFF_FIXTURES_2370_2370 = [
    {
        name: "ringbuf-map-get-rejects-event-map-kind"
        category: "maps"
        tags: [maps ringbuf map-get diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  let entry = ($ctx.pid | map-get events --kind ringbuf)'
            '  if $entry { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get --kind ringbuf is reserved for ring-buffer event maps"
    }
]
