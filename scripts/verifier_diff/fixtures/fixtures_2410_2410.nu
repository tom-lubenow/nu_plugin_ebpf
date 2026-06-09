const VERIFIER_DIFF_FIXTURES_2410_2410 = [
    {
        name: "user-ringbuf-map-define-rejects-helper-surface-kind"
        category: "maps"
        tags: [maps user-ringbuf map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define events --kind user-ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind user-ringbuf is reserved for user-ringbuf helper surfaces"
    }
]
