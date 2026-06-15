export const VERIFIER_DIFF_FIXTURES_3849_3849 = [
    {
        name: "map-put-array-i32-math-abs-sum"
        category: "maps"
        tags: [maps map-define map-put map-get arrays i32 math abs sum accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define nums --kind array --value-type "array{i32:2}" --max-entries 1'
            '  [-3 5] | map-put nums 0 --kind array'
            '  let entry = (0 | map-get nums --kind array)'
            '  if $entry {'
            '    (($entry | math abs | math sum) == 8)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
