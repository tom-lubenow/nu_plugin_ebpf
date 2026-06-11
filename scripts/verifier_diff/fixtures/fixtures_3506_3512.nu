export const VERIFIER_DIFF_FIXTURES_3506_3512 = [
    {
        name: "map-get-array-u32-uniq-length"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-i32-uniq-length"
        category: "maps"
        tags: [maps map-define map-get arrays i32 uniq length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{i32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | length) == 1)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-uniq-first"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | first) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-uniq-math-min"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq math min accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | math min) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-uniq-math-max"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq math max accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | math max) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-uniq-math-sum"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | math sum) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-uniq-math-product"
        category: "maps"
        tags: [maps map-define map-get arrays u32 uniq math product accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | uniq | math product) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
