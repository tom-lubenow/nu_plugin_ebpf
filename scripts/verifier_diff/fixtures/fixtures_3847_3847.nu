export const VERIFIER_DIFF_FIXTURES_3847_3847 = [
    {
        name: "map-put-array-bool-all-true"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool all accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [true true] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    $entry | all {|x| $x }'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
