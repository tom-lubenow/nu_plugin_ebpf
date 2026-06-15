export const VERIFIER_DIFF_FIXTURES_3836_3836 = [
    {
        name: "map-put-array-bool-take-last"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool take last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [true false] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | take 1 | last) == true)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
