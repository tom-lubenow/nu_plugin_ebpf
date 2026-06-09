const VERIFIER_DIFF_FIXTURES_2414_2414 = [
    {
        name: "array-of-maps-map-define-rejects-missing-max-entries"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --kind array-of-maps requires --max-entries for the outer map"
    }
]
