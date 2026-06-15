export const VERIFIER_DIFF_FIXTURES_3846_3846 = [
    {
        name: "map-put-array-bool-any-true"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool any accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [false true] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    $entry | any {|x| $x }'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
