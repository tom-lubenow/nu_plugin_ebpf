const VERIFIER_DIFF_FIXTURES_2439_2441 = [
    {
        name: "map-put-dynamic-inner-map-rejects-kind"
        category: "maps"
        tags: [maps map-in-map map-put dynamic-update diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    99 | map-put $inner 7 --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-put on a dynamic inner-map pointer does not accept --kind"
    }
    {
        name: "map-delete-dynamic-inner-map-rejects-named-arguments"
        category: "maps"
        tags: [maps map-in-map map-delete dynamic-delete diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    7 | map-delete $inner --kind hash'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-delete on a dynamic inner-map pointer does not accept named arguments"
    }
    {
        name: "map-contains-dynamic-inner-map-rejects-named-arguments"
        category: "maps"
        tags: [maps map-in-map map-contains dynamic-lookup diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type int --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    let present = (7 | map-contains $inner --kind hash)'
            '    if $present { 1 }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-contains on a dynamic inner-map pointer does not accept named arguments"
    }
]
