const VERIFIER_DIFF_FIXTURES_2382_2382 = [
    {
        name: "perf-event-array-map-delete-rejects-output-map-kind"
        category: "maps"
        tags: [maps perf-event-array map-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  0 | map-delete perf_events --kind perf-event-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete --kind perf-event-array is reserved for perf-event output maps"
    }
]
