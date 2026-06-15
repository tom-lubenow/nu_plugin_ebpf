export const VERIFIER_DIFF_FIXTURES_3832_3832 = [
    {
        name: "map-put-array-bool-reverse-first"
        category: "maps"
        tags: [maps map-define map-put map-get arrays bool reverse first accept]
        target: "raw_tracepoint:sys_enter"
        program: [
            '{|ctx|'
            '  map-define flags --kind array --value-type "array{bool:2}" --max-entries 1'
            '  [true false] | map-put flags 0 --kind array'
            '  let entry = (0 | map-get flags --kind array)'
            '  if $entry {'
            '    (($entry | reverse | first) == false)'
            '  } else {'
            '    false'
            '  }'
            '}'
        ]
        local: "accept"
        kernel: "accept"
    }
]
