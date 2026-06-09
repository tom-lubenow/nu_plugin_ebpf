const VERIFIER_DIFF_FIXTURES_2415_2415 = [
    {
        name: "map-in-map-inner-template-ambiguous-name-rejects"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define inner_seen --kind array --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --inner-map 'inner_seen' is ambiguous"
    }
]
