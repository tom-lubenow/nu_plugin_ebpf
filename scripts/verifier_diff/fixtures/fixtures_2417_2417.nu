const VERIFIER_DIFF_FIXTURES_2417_2417 = [
    {
        name: "map-in-map-inner-template-conflict-rejects"
        category: "maps"
        tags: [maps map-in-map array-of-maps map-define diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_a --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define inner_b --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_a --max-entries 4'
            '  map-define outer_array --kind array-of-maps --inner-map inner_b --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-define --inner-map inner map template for 'outer_array' conflicts with earlier declaration"
    }
]
