export const VERIFIER_DIFF_FIXTURES_3423_3424 = [
    {
        name: "map-delete-dynamic-inner-map"
        category: "language-surface"
        tags: [maps map-in-map map-delete dynamic-delete accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    7 | map-delete $inner'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
    {
        name: "map-contains-dynamic-inner-map"
        category: "language-surface"
        tags: [maps map-in-map map-contains dynamic-lookup accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    if (7 | map-contains $inner) {'
            '      return 1'
            '    }'
            '  }'
            '  0'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
