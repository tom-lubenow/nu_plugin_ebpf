export const VERIFIER_DIFF_FIXTURES_3513_3517 = [
    {
        name: "map-get-array-u32-math-min"
        category: "maps"
        tags: [maps map-define map-get arrays u32 math min accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | math min) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-math-max"
        category: "maps"
        tags: [maps map-define map-get arrays u32 math max accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | math max) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-u32-math-product"
        category: "maps"
        tags: [maps map-define map-get arrays u32 math product accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | math product) == 0)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bool-any-false"
        category: "maps"
        tags: [maps map-define map-get arrays bool any closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    $entry | any {|x| $x == false }'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
    {
        name: "map-get-array-bool-all-false"
        category: "maps"
        tags: [maps map-define map-get arrays bool all closure accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    $entry | all {|x| $x == false }'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
