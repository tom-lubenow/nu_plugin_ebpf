export const VERIFIER_DIFF_FIXTURES_3843_3843 = [
    {
        name: "map-put-array-bool-where-true-length"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool where closure length accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:3}" --max-entries 1'
            '  [true false true] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | where {|x| $x } | length) == 2)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
