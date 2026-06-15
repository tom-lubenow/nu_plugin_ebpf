export const VERIFIER_DIFF_FIXTURES_3842_3842 = [
    {
        name: "map-put-array-bool-where-false-is-empty"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool where closure is-empty accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:3}" --max-entries 1'
            '  [true false true] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | where {|x| false } | is-empty) == true)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
