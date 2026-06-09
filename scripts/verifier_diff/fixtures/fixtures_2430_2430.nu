const VERIFIER_DIFF_FIXTURES_2430_2430 = [
    {
        name: "map-define-rejects-conflicting-max-entries"
        category: "maps"
        tags: [maps map-define schema diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define seen --kind array --value-type u64 --max-entries 4'
            '  map-define seen --kind array --value-type u64 --max-entries 8'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define max entries for 'seen' conflicts with declared map schema"
    }
]
