export const VERIFIER_DIFF_FIXTURES_3861_3861 = [
    {
        name: "array-of-maps-dynamic-inner-bool-array-value-put-get"
        category: "maps"
        tags: [maps map-in-map array-of-maps dynamic-update dynamic-lookup arrays bool value-type map-put map-get get accept]
        default_test_lane: "dry-run"
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define inner_bool_slots --kind hash --key-type u32 --value-type "array{bool:2}" --max-entries 16'
            '  map-define outer_bool_slots --kind array-of-maps --inner-map inner_bool_slots --max-entries 4'
            '  let inner = (0 | map-get outer_bool_slots)'
            '  if $inner {'
            '    [true false] | map-put $inner 7'
            '    let stored = (7 | map-get $inner)'
            '    if $stored {'
            '      return (($stored | get 0) and (not ($stored | get 1)))'
            '    }'
            '  }'
            '  false'
            '}'
        ]
        local: "accept"
        kernel: "skip"
    }
]
