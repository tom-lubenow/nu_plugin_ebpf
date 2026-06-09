const VERIFIER_DIFF_FIXTURES_2404_2404 = [
    {
        name: "perf-event-array-map-define-rejects-output-map-kind"
        category: "maps"
        tags: [maps perf-event-array map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define perf_events --kind perf-event-array'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind perf-event-array is reserved for perf-event output maps"
    }
]
