const VERIFIER_DIFF_FIXTURES_2405_2405 = [
    {
        name: "ringbuf-map-define-rejects-event-map-kind"
        category: "maps"
        tags: [maps ringbuf map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ring_events --kind ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind ringbuf is reserved for ring-buffer event maps"
    }
]
