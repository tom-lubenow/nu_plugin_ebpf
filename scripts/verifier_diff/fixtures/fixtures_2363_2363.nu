const VERIFIER_DIFF_FIXTURES_2363_2363 = [
    {
        name: "user-ringbuf-map-put-rejects-kind"
        category: "maps"
        tags: [maps user-ringbuf map-put diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  $ctx.arg0 | map-put events $ctx.pid --kind user-ringbuf'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "reserved for user-ringbuf helper surfaces"
    }
]
