const VERIFIER_DIFF_FIXTURES_2381_2381 = [
    {
        name: "ringbuf-map-delete-rejects-event-map-kind"
        category: "maps"
        tags: [maps ringbuf map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete events --kind ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind ringbuf is reserved for ring-buffer event maps"
    }
]
