const VERIFIER_DIFF_FIXTURES_2386_2386 = [
    {
        name: "user-ringbuf-map-delete-rejects-helper-surface-kind"
        category: "maps"
        tags: [maps user-ringbuf map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete events --kind user-ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind user-ringbuf is reserved for user-ringbuf helper surfaces"
    }
]
