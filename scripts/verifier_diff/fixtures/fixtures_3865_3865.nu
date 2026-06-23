export const VERIFIER_DIFF_FIXTURES_3865_3865 = [
    {
        name: "queue-map-contains-rejects-kind"
        category: "maps"
        tags: [maps queue map-contains diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  if (0 | map-contains recent_args --kind queue) { 1 } else { 0 }'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "use map-peek to read entries or map-pop to read and remove entries"
    }
]
