export const VERIFIER_DIFF_FIXTURES_3848_3848 = [
    {
        name: "map-put-array-u32-math-sum"
        category: "maps"
        tags: [maps map-define map-put map-get arrays u32 math sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define ports --kind array --value-type "array{u32:2}" --max-entries 1'
            '  [7 11] | map-put ports 0 --kind array'
            '  let entry = (0 | map-get ports --kind array)'
            '  if $entry {'
            '    (($entry | math sum) == 18)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
