export const VERIFIER_DIFF_FIXTURES_3835_3835 = [
    {
        name: "map-put-array-bool-last"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool last accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [true false] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | last) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
