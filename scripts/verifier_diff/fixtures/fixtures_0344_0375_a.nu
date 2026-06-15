const VERIFIER_DIFF_FIXTURES_0344_0375_A = [
    {
        name: "map-define-hash-of-maps-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash --kind hash-of-maps)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-hash-of-maps-inferred-operation-accepts"
        category: "maps"
        tags: [maps map-define map-in-map kind-inference accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --key-type u32 --inner-map inner_seen --max-entries 4'
            '  let entry = (0 | map-get outer_hash)'
            '  if $entry { 1 }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-define-map-in-map-rejects-missing-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "requires --inner-map"
    }
    {
        name: "map-define-map-in-map-rejects-self-inner-map"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define outer_array --kind array-of-maps --inner-map outer_array --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "cannot use itself as its inner map template"
    }
    {
        name: "map-define-map-in-map-rejects-nested-inner-template"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define leaf_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define inner_outer --kind array-of-maps --inner-map leaf_seen --max-entries 4'
            '  map-define outer_array --kind array-of-maps --inner-map inner_outer --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "must name a previously declared inner map with --value-type"
    }
    {
        name: "map-define-map-in-map-rejects-outer-value-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --value-type u64 --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "--value-type is not supported for map-in-map outer map"
    }
    {
        name: "map-define-hash-of-maps-rejects-missing-key-type"
        category: "maps"
        tags: [maps map-define map-in-map reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_hash --kind hash-of-maps --inner-map inner_seen --max-entries 4'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "hash-of-maps requires --key-type"
    }
]
