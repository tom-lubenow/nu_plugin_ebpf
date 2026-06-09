const VERIFIER_DIFF_FIXTURES_2438_2438 = [
    {
        name: "map-get-dynamic-inner-map-rejects-named-arguments"
        category: "maps"
        tags: [maps map-in-map map-get dynamic-lookup diagnostics reject]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_seen --kind hash --key-type u32 --value-type u64 --max-entries 16'
            '  map-define outer_array --kind array-of-maps --inner-map inner_seen --max-entries 4'
            '  let inner = (0 | map-get outer_array)'
            '  if $inner {'
            '    let value = (7 | map-get $inner --kind hash)'
            '    if $value { $value | count }'
            '  }'
            '  0'
            '}'
        ]
        local: "reject"
        kernel: "skip"
        error_contains: "map-get on a dynamic inner-map pointer does not accept named arguments"
    }
]
